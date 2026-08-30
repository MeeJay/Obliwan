// ============================================================================
// @obliwan/shared — the Site Intent contract (M11 — K4)
// ============================================================================
//
// ┌─ WHAT THIS FILE IS FOR ───────────────────────────────────────────────────┐
// │ A technician who only knows MikroTik must be able to deploy a DrayTek.    │
// │ The way that happens is NOT a wizard that hides the CLI — it is a         │
// │ declarative description of what the SITE must be (`SiteIntent`), and a    │
// │ compiler that turns it into the NCM of a specific box.                    │
// │                                                                           │
// │ The vendor knowledge therefore has to leave the senior engineer's head    │
// │ and enter the product as DATA. Two tables carry it:                       │
// │   - `DeviceCapabilities` (device.ts), whose default is NO_CAPABILITIES;   │
// │   - `IntentSupport` (here), whose default is NO_INTENT_SUPPORT.           │
// │ Both default to "does not know how to". A brand gains a feature only      │
// │ because somebody wrote `true` next to it, never because a field was       │
// │ forgotten.                                                                │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ THE PROPERTY THAT MAKES K4 WORTH BUILDING ───────────────────────────────┐
// │ Compilation fails BEFORE any network access when the hardware cannot do   │
// │ what the intent asks. Not at apply time, not half-way through a push, and │
// │ not as a device that "somehow did not get the VLANs". `capabilityCheck`   │
// │ runs on declarative data only: no socket, no session, no credential.      │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ §8.2 — MADE STRUCTURAL, NOT POLICED ─────────────────────────────────────┐
// │ There is NO field in this schema in which a secret can be typed. A PPPoE  │
// │ password, an IPsec PSK, an SNMP community and a local user's password are │
// │ all `SecretRef` — a pointer into the vault. The compiler emits            │
// │ `<<secret:…>>` placeholders in the artefact and an `unavailable`          │
// │ fingerprint in the NCM; the plaintext is injected on the vault → device   │
// │ path (M6) and exists in memory only.                                      │
// │                                                                           │
// │ This is deliberately stronger than a redaction pass. The last audit found │
// │ the L2TP passwords of an entire fleet inside a jsonb column that was      │
// │ being served to the UI. A redactor that is not called leaks; a field that │
// │ does not exist cannot.                                                    │
// └───────────────────────────────────────────────────────────────────────────┘
//
// NOT exported from `src/index.ts` — that barrel belongs to another workstream
// this milestone may not edit. Import it as `@obliwan/shared/dist/intent`,
// exactly as `query.ts` is imported by the M9 services.

import { z } from 'zod';
import type { DeviceBrand, DeviceCapabilities, DeviceCapabilityFlag, DeviceFamily } from './device';
import { parseCidr } from './ncm/primitives';
import { NCM_RESOURCE_KINDS } from './ncm/resources';

/** Bumped on ANY change to the shape of `SiteIntent`. Stored on every row and
 *  on every compilation, so a document can always be read by the code that
 *  wrote it. */
export const INTENT_SCHEMA_VERSION = 1;

/**
 * Bumped when the RENDERING of any brand changes. It is part of every golden
 * file and of `intent_compilations.compiler_version`: "the artefact changed and
 * nobody touched the intent" must have an answer other than a shrug — the same
 * argument as `saved_queries.compiled_sql_hash` in M9.
 */
export const INTENT_COMPILER_VERSION = 1;

// ============================================================================
// Primitives
// ============================================================================

/** Lowercase identifier used for segment ids and for the `obliwan:<slug>`
 *  marker that anchors drift pairing to what we wrote. */
/**
 * FREE TEXT THAT WILL BE INTERPOLATED INTO A CONFIGURATION LINE.
 *
 * A segment name, a rule comment, a DHCP domain, a reservation hostname, a
 * local username: all of them are written by whoever holds TEMPLATE_WRITE
 * and all of them come back out inside a line of RouterOS script, Vigor CLI
 * or ZLD CLI. A single `\n` in one of them ends our line and starts one of
 * theirs — `x"\n/user add name=bd group=full\n#` in a LAN name rendered
 * sixteen standalone `/user add` lines into a RouterOS artefact, and a plan
 * reviewer reading a renamed segment approved an unauthenticated `full`
 * administrator on the customer's router.
 *
 * The renderers escape (see `rosQuote` / `vigorText` / `zldText` /
 * `token` in server/src/services/intent/renderers.ts) and that is the
 * barrier. This regex is the door: it means the operator gets a 400 naming
 * the field instead of a silently mangled comment, and it means a second
 * renderer written next year starts life safe.
 *
 * Deliberately a blacklist of the four characters that end a line or a
 * quoted string, not a whitelist: a French site is called "Lyon Nord —
 * étage 2", and a schema that refused the accent would be worked around
 * rather than obeyed.
 */
const SAFE_TEXT = /^[^\r\n"\\]*$/;
const SAFE_TEXT_MESSAGE =
  'line breaks, double quotes and backslashes are refused here: this text is interpolated into a device configuration line';

export const IntentSlug = z
  .string()
  .min(2)
  .max(40)
  .regex(/^[a-z][a-z0-9-]*[a-z0-9]$/, 'slug must be lowercase alphanumeric with dashes');
export type IntentSlug = z.infer<typeof IntentSlug>;

/**
 * A pointer into the vault. NEVER a value.
 *
 * The `ref:` prefix is mandatory so that a human pasting a password into the
 * field produces a validation error rather than a silently accepted secret.
 */
export const SecretRef = z
  .string()
  .min(6)
  .max(80)
  .regex(
    /^ref:[a-z0-9][a-z0-9._-]{2,70}$/,
    'a secret is referenced as "ref:<vault-label>", never given inline',
  );
export type SecretRef = z.infer<typeof SecretRef>;

/** What a compiled artefact carries where a secret will later be injected. */
export const SECRET_PLACEHOLDER_PREFIX = '<<secret:';

/** The placeholder for one vault reference. The M6 push path is the only code
 *  allowed to replace it, in memory, on the way to the device. */
export function secretPlaceholder(ref: string): string {
  return `${SECRET_PLACEHOLDER_PREFIX}${ref.replace(/^ref:/, '')}>>`;
}

const cidrString = (opts: { host: boolean }) =>
  z
    .string()
    .min(4)
    .max(49)
    .refine(
      (v) => {
        const c = parseCidr(v);
        if (!c) return false;
        const width = c.version === 4 ? 32 : 128;
        // A host declaration on a /32 is a configuration mistake that only
        // surfaces on the device, hours later.
        return opts.host ? c.prefix < width : true;
      },
      opts.host
        ? 'expected an interface address with a prefix, e.g. 10.20.0.1/24'
        : 'expected a CIDR',
    );

const ipString = z
  .string()
  .min(3)
  .max(45)
  .refine((v) => {
    if (v.includes('/')) return false;
    const c = parseCidr(v);
    return !!c;
  }, 'expected a bare IP address');

// ============================================================================
// The intent
// ============================================================================

export const WAN_MODES = ['dhcp', 'static', 'pppoe'] as const;
export type WanMode = (typeof WAN_MODES)[number];

export const WAN_ROLES = ['primary', 'backup'] as const;
export type WanRole = (typeof WAN_ROLES)[number];

export const WanUplink = z
  .object({
    id: IntentSlug,
    role: z.enum(WAN_ROLES),
    mode: z.enum(WAN_MODES),
    /** 1-based physical uplink. The brand profile maps it to `ether1`, `WAN1`,
     *  `ge1`, `X1` — the technician never types a brand port name. */
    uplinkIndex: z.number().int().min(1).max(4),
    /** Required by `mode: 'static'`, forbidden otherwise (see `superRefine`). */
    address: cidrString({ host: true }).nullable(),
    gateway: ipString.nullable(),
    /** Operator-imposed VLAN tag on the uplink (common on FTTH hand-offs). */
    vlanId: z.number().int().min(1).max(4094).nullable(),
    /** Required by `mode: 'pppoe'`. The password is a vault reference. */
    pppoeUsername: z.string().max(128).regex(SAFE_TEXT, SAFE_TEXT_MESSAGE).nullable(),
    pppoeSecretRef: SecretRef.nullable(),
    mtu: z.number().int().min(576).max(9216).nullable(),
  })
  .strict();
export type WanUplink = z.infer<typeof WanUplink>;

export const DhcpReservationIntent = z
  .object({
    mac: z.string().regex(/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/, 'lowercase colon-separated MAC'),
    address: ipString,
    hostname: z.string().max(128).regex(SAFE_TEXT, SAFE_TEXT_MESSAGE).nullable(),
  })
  .strict();
export type DhcpReservationIntent = z.infer<typeof DhcpReservationIntent>;

export const DhcpIntent = z
  .object({
    poolFrom: ipString,
    poolTo: ipString,
    dnsServers: z.array(ipString).max(4),
    domain: z.string().max(128).regex(SAFE_TEXT, SAFE_TEXT_MESSAGE).nullable(),
    leaseSeconds: z.number().int().min(60).max(604800),
    reservations: z.array(DhcpReservationIntent).max(128),
  })
  .strict();
export type DhcpIntent = z.infer<typeof DhcpIntent>;

export const LanSegment = z
  .object({
    id: IntentSlug,
    name: z.string().min(1).max(64).regex(SAFE_TEXT, SAFE_TEXT_MESSAGE),
    /** null = the native / untagged segment. */
    vlanId: z.number().int().min(1).max(4094).nullable(),
    /** The gateway address WITH its prefix: `10.20.0.1/24` says both "this is
     *  the subnet" and "the box is .1 in it". */
    gatewayCidr: cidrString({ host: true }),
    dhcp: DhcpIntent.nullable(),
    /** Guest posture: the segment reaches the internet and nothing else. */
    isolated: z.boolean(),
    internetAccess: z.boolean(),
    /** Which physical ports carry it untagged. Brand-neutral 1-based indices. */
    accessPorts: z.array(z.number().int().min(1).max(48)).max(48),
  })
  .strict();
export type LanSegment = z.infer<typeof LanSegment>;

export const IP_PROTOCOLS = ['tcp', 'udp'] as const;

export const PortForward = z
  .object({
    id: IntentSlug,
    /** `WanUplink.id` this publication listens on. */
    wan: IntentSlug,
    protocol: z.enum(IP_PROTOCOLS),
    externalPort: z.number().int().min(1).max(65535),
    /** `LanSegment.id` the target lives in — used to derive the zone. */
    toSegment: IntentSlug,
    toAddress: ipString,
    toPort: z.number().int().min(1).max(65535),
    /** Source restriction. Empty = published to the whole internet, which the
     *  compiler surfaces as a warning rather than hides. */
    fromSources: z.array(cidrString({ host: false })).max(16),
    comment: z.string().max(120).regex(SAFE_TEXT, SAFE_TEXT_MESSAGE).nullable(),
  })
  .strict();
export type PortForward = z.infer<typeof PortForward>;

export const ZoneRule = z
  .object({
    id: IntentSlug,
    /** `LanSegment.id`, or the reserved names `wan` / `any`. */
    from: IntentSlug,
    to: IntentSlug,
    action: z.enum(['allow', 'deny']),
    protocol: z.enum(IP_PROTOCOLS).nullable(),
    ports: z.array(z.number().int().min(1).max(65535)).max(32),
    comment: z.string().max(120).regex(SAFE_TEXT, SAFE_TEXT_MESSAGE).nullable(),
  })
  .strict();
export type ZoneRule = z.infer<typeof ZoneRule>;

export const SitePolicy = z
  .object({
    /** What happens to unsolicited inbound traffic. There is no `accept`. */
    defaultInbound: z.enum(['drop', 'reject']),
    /** Segments may talk to each other unless this says otherwise. */
    interSegment: z.enum(['deny', 'allow']),
    allowPingFromWan: z.boolean(),
    publish: z.array(PortForward).max(64),
    /** Zone-to-zone policy. NON-EMPTY requires a brand with a zone model —
     *  which MikroTik and DrayTek do not have (see `Zone` in ncm/primitives). */
    zones: z.array(ZoneRule).max(64),
  })
  .strict();
export type SitePolicy = z.infer<typeof SitePolicy>;

export const IKE_MODES = ['ike2', 'ike1-main'] as const;

export const VpnTunnel = z
  .object({
    id: IntentSlug,
    remote: z.string().min(3).max(255).regex(SAFE_TEXT, SAFE_TEXT_MESSAGE),
    exchangeMode: z.enum(IKE_MODES),
    /** The PSK lives in the vault. This is its label. */
    pskRef: SecretRef,
    localSubnets: z.array(cidrString({ host: false })).min(1).max(16),
    remoteSubnets: z.array(cidrString({ host: false })).min(1).max(16),
    encryption: z.array(z.string().max(24)).min(1).max(6),
    integrity: z.array(z.string().max(24)).min(1).max(6),
    dhGroup: z.array(z.string().max(24)).min(1).max(6),
    dpdSeconds: z.number().int().min(5).max(3600).nullable(),
  })
  .strict();
export type VpnTunnel = z.infer<typeof VpnTunnel>;

export const MANAGED_SERVICES = ['ssh', 'https', 'winbox', 'api-ssl', 'snmp'] as const;
export type ManagedService = (typeof MANAGED_SERVICES)[number];

export const ManagementService = z
  .object({
    service: z.enum(MANAGED_SERVICES),
    enabled: z.boolean(),
    /** Empty means "from anywhere", which is what K5's first query hunts for.
     *  The compiler warns; it does not silently narrow. */
    allowedFrom: z.array(cidrString({ host: false })).max(16),
    port: z.number().int().min(1).max(65535).nullable(),
  })
  .strict();
export type ManagementService = z.infer<typeof ManagementService>;

/**
 * The versions an intent may ASK FOR — deliberately narrower than
 * `telemetry.SNMP_VERSIONS`, which also carries `v1`.
 *
 * We must be able to POLL v1, because old gear exists and refusing to read it
 * would just hide it. We must never DEPLOY v1: it has no authentication at all,
 * and "who is still on SNMP v1" is one of the questions Fleet Query (M9) exists
 * to answer. Reading a weakness and writing one are not the same act, so they do
 * not share a list.
 */
export const SNMP_INTENT_VERSIONS = ['v2c', 'v3'] as const;
export type SnmpIntentVersion = (typeof SNMP_INTENT_VERSIONS)[number];

export const SnmpIntent = z
  .object({
    version: z.enum(SNMP_INTENT_VERSIONS),
    /** v2c community OR v3 auth material — both are vault references. */
    credentialRef: SecretRef,
    username: z.string().max(64).regex(SAFE_TEXT, SAFE_TEXT_MESSAGE).nullable(),
    allowedFrom: z.array(cidrString({ host: false })).max(8),
  })
  .strict();
export type SnmpIntent = z.infer<typeof SnmpIntent>;

export const LocalUserIntent = z
  .object({
    username: z.string().min(1).max(64).regex(SAFE_TEXT, SAFE_TEXT_MESSAGE),
    group: z.enum(['full', 'read', 'write']),
    passwordRef: SecretRef,
    allowedFrom: z.array(cidrString({ host: false })).max(8),
  })
  .strict();
export type LocalUserIntent = z.infer<typeof LocalUserIntent>;

export const ManagementIntent = z
  .object({
    services: z.array(ManagementService).max(16),
    snmp: SnmpIntent.nullable(),
    localUsers: z.array(LocalUserIntent).max(16),
  })
  .strict();
export type ManagementIntent = z.infer<typeof ManagementIntent>;

export const QosSegmentLimit = z
  .object({
    segment: IntentSlug,
    maxDownBps: z.number().int().min(64_000).nullable(),
    maxUpBps: z.number().int().min(64_000).nullable(),
    priority: z.number().int().min(1).max(8).nullable(),
  })
  .strict();
export type QosSegmentLimit = z.infer<typeof QosSegmentLimit>;

export const QosIntent = z
  .object({
    /** `WanUplink.id` the shaper hangs off. */
    wan: IntentSlug,
    downBps: z.number().int().min(64_000),
    upBps: z.number().int().min(64_000),
    segments: z.array(QosSegmentLimit).max(16),
  })
  .strict();
export type QosIntent = z.infer<typeof QosIntent>;

/**
 * What the operator demands of the SAFETY NET, not of the network.
 *
 * Every flag here is opt-in and every one of them maps onto a
 * `DeviceCapabilities` flag of `device.ts` (see `FEATURE_REQUIRES_FLAGS` and
 * `FEATURE_FORBIDS_FLAGS`). This is the join between "what the site must be"
 * and "what this box is declared able to do".
 */
export const SafetyIntent = z
  .object({
    /** §8.3 ARMED: a dead-man ON the device (`start-time=startup`). */
    requireOnDeviceDeadMan: z.boolean(),
    /** Writes stage and are committed all-or-nothing (SonicOS pending config). */
    requireAtomicCommit: z.boolean(),
    /** The change may not cost a reboot — rules out DrayTek's `.cfg` restore. */
    forbidRebootToApply: z.boolean(),
    /** Drift must be diffable line by line, not an opaque fingerprint. */
    requireStructuredDiff: z.boolean(),
  })
  .strict();
export type SafetyIntent = z.infer<typeof SafetyIntent>;

export const SiteIntentBody = z
  .object({
    schemaVersion: z.literal(INTENT_SCHEMA_VERSION),
    /** Anchors every `obliwan:<slug>.<record>` marker the compiler emits. */
    slug: IntentSlug,
    name: z.string().min(1).max(120).regex(SAFE_TEXT, SAFE_TEXT_MESSAGE),
    description: z.string().max(1000).regex(SAFE_TEXT, SAFE_TEXT_MESSAGE).nullable(),
    wan: z.array(WanUplink).min(1).max(4),
    lans: z.array(LanSegment).min(1).max(16),
    policy: SitePolicy,
    vpn: z.array(VpnTunnel).max(8),
    management: ManagementIntent,
    qos: QosIntent.nullable(),
    safety: SafetyIntent,
    /**
     * THE MOST DANGEROUS FIELD IN THIS FILE, AND IT IS OPT-IN FOR THAT REASON.
     *
     * The NCM kinds this intent claims to own EXHAUSTIVELY. Only those get
     * `coverage: 'complete'` in the compiled document; every other kind the
     * compiler writes is `'partial'`.
     *
     * `coverage: 'complete'` on the DESIRED side is what authorises the diff
     * engine to emit `extra` — "this exists on the device and the intent does
     * not want it" — which the planner turns into a deletion. A site build that
     * claimed completeness on `firewallRule` by default would therefore compile
     * a plan that deletes every firewall rule the customer added by hand.
     *
     * So the claim is an explicit, auditable gesture, exactly as a template
     * that means "this chain must be EMPTY" has to declare the section rather
     * than say nothing about it. The default — an empty array — can only ever
     * produce `changed` findings on records ObliWAN itself wrote.
     */
    authoritative: z.array(z.enum(NCM_RESOURCE_KINDS)).max(NCM_RESOURCE_KINDS.length),
  })
  .strict();

/**
 * Cross-field rules. They live in a `superRefine` rather than in the compiler
 * because an intent that references a segment it does not declare is not a
 * compilation failure of one brand — it is an invalid document, and it must be
 * rejected identically by the API, by an import and by a unit test.
 */
export const SiteIntentDocument = SiteIntentBody.superRefine((intent, ctx) => {
  const segmentIds = new Set(intent.lans.map((l) => l.id));
  const wanIds = new Set(intent.wan.map((w) => w.id));

  const dup = (label: string, ids: string[], path: (string | number)[]): void => {
    const seen = new Set<string>();
    ids.forEach((id, i) => {
      if (seen.has(id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [...path, i, 'id'],
          message: `duplicate ${label} id "${id}"`,
        });
      }
      seen.add(id);
    });
  };
  dup('WAN', intent.wan.map((w) => w.id), ['wan']);
  dup('segment', intent.lans.map((l) => l.id), ['lans']);
  dup('publication', intent.policy.publish.map((p) => p.id), ['policy', 'publish']);
  dup('zone rule', intent.policy.zones.map((r) => r.id), ['policy', 'zones']);
  dup('tunnel', intent.vpn.map((v) => v.id), ['vpn']);

  intent.wan.forEach((w, i) => {
    if (w.mode === 'static' && (!w.address || !w.gateway)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['wan', i, 'address'],
        message: 'a static uplink needs both an address and a gateway',
      });
    }
    if (w.mode !== 'static' && (w.address || w.gateway)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['wan', i, 'address'],
        message: `a "${w.mode}" uplink learns its address; do not state one`,
      });
    }
    if (w.mode === 'pppoe' && (!w.pppoeUsername || !w.pppoeSecretRef)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['wan', i, 'pppoeUsername'],
        message: 'a PPPoE uplink needs a username and a vault reference for its password',
      });
    }
    if (w.mode !== 'pppoe' && (w.pppoeUsername || w.pppoeSecretRef)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['wan', i, 'pppoeUsername'],
        message: 'PPPoE credentials on a non-PPPoE uplink',
      });
    }
  });
  if (intent.wan.filter((w) => w.role === 'primary').length !== 1) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['wan'],
      message: 'exactly one uplink must be the primary',
    });
  }
  const uplinkIndexes = new Set<number>();
  intent.wan.forEach((w, i) => {
    if (uplinkIndexes.has(w.uplinkIndex)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['wan', i, 'uplinkIndex'],
        message: `two uplinks claim physical port ${w.uplinkIndex}`,
      });
    }
    uplinkIndexes.add(w.uplinkIndex);
  });

  // A DHCP pool outside its own subnet is the most common site-build mistake,
  // and on most brands the device accepts it and hands out unroutable leases.
  intent.lans.forEach((l, i) => {
    if (!l.dhcp) return;
    const bounds: ReadonlyArray<readonly ['poolFrom' | 'poolTo', string]> = [
      ['poolFrom', l.dhcp.poolFrom],
      ['poolTo', l.dhcp.poolTo],
    ];
    for (const [field, value] of bounds) {
      if (!addressInSubnet(value, l.gatewayCidr)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['lans', i, 'dhcp', field],
          message: `${value} is outside ${l.gatewayCidr}`,
        });
      }
    }
    l.dhcp.reservations.forEach((r, j) => {
      if (!addressInSubnet(r.address, l.gatewayCidr)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['lans', i, 'dhcp', 'reservations', j, 'address'],
          message: `${r.address} is outside ${l.gatewayCidr}`,
        });
      }
    });
  });

  intent.policy.publish.forEach((p, i) => {
    if (!wanIds.has(p.wan)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['policy', 'publish', i, 'wan'],
        message: `unknown uplink "${p.wan}"`,
      });
    }
    if (!segmentIds.has(p.toSegment)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['policy', 'publish', i, 'toSegment'],
        message: `unknown segment "${p.toSegment}"`,
      });
    }
  });
  intent.policy.zones.forEach((r, i) => {
    for (const side of ['from', 'to'] as const) {
      const v = r[side];
      if (v !== 'wan' && v !== 'any' && !segmentIds.has(v)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['policy', 'zones', i, side],
          message: `unknown zone "${v}" (expected a segment id, "wan" or "any")`,
        });
      }
    }
  });
  if (intent.qos) {
    if (!wanIds.has(intent.qos.wan)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['qos', 'wan'],
        message: `unknown uplink "${intent.qos.wan}"`,
      });
    }
    intent.qos.segments.forEach((s, i) => {
      if (!segmentIds.has(s.segment)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['qos', 'segments', i, 'segment'],
          message: `unknown segment "${s.segment}"`,
        });
      }
    });
  }
});
export type SiteIntentDocument = z.infer<typeof SiteIntentDocument>;

// NOTE, deliberately not a schema: there is NO permissive `SiteIntentStored`
// reader here, unlike `NcmDocumentStored` in the NCM contract. The asymmetry is
// intentional. A snapshot is an OBSERVATION and losing a field a newer server
// wrote would destroy data, so it is read with `.passthrough()`. An intent is an
// INSTRUCTION: compiling one whose shape nothing validated would push an
// artefact built from fields no schema checked onto a customer's firewall.
// `intentStore.service` therefore parses stored rows strictly and fails loudly.

/** Whether a bare address sits inside a CIDR. Exported because the compiler
 *  re-uses it to place a port-forward target in the right segment. */
export function addressInSubnet(address: string, cidr: string): boolean {
  const a = parseCidr(address);
  const n = parseCidr(cidr);
  if (!a || !n || a.version !== n.version) return false;
  for (let bit = 0; bit < n.prefix; bit++) {
    const byte = bit >> 3;
    const mask = 0x80 >> (bit & 7);
    if ((a.bytes[byte] & mask) !== (n.bytes[byte] & mask)) return false;
  }
  return true;
}

// ============================================================================
// The feature vocabulary — what an intent can ASK a box to do
// ============================================================================

/**
 * Every capability an intent can require, named the way an error message needs
 * to name it. This list is the product's vendor-knowledge index: adding a
 * feature means adding a row to every brand profile, and the server will not
 * compile until each brand has answered yes or no.
 */
export const INTENT_FEATURES = [
  'wan.dhcp',
  'wan.static',
  'wan.pppoe',
  'wan.vlanTag',
  'wan.multiUplink',

  'lan.multiSegment',
  'lan.vlanSegmentation',
  'lan.dhcpServer',
  'lan.dhcpReservation',
  'lan.segmentIsolation',

  'policy.statefulFirewall',
  'policy.zoneModel',
  'policy.portForward',
  'policy.interSegmentControl',
  'policy.icmpControl',

  'vpn.ipsecSiteToSite',
  'vpn.ikev2',

  'mgmt.serviceRestriction',
  'mgmt.localUsers',
  'mgmt.snmpV3',

  'qos.shaping',
  'qos.perSegmentPriority',

  'safety.onDeviceDeadMan',
  'safety.atomicCommit',
  'safety.noRebootApply',
  'safety.structuredDiff',
] as const;
export type IntentFeature = (typeof INTENT_FEATURES)[number];

/** What the operator reads when the compilation is refused. */
export const INTENT_FEATURE_LABELS: Readonly<Record<IntentFeature, string>> = {
  'wan.dhcp': 'WAN uplink addressed by DHCP',
  'wan.static': 'WAN uplink with a static address',
  'wan.pppoe': 'PPPoE uplink',
  'wan.vlanTag': 'VLAN tag on the WAN uplink',
  'wan.multiUplink': 'more than one WAN uplink (failover)',
  'lan.multiSegment': 'more than one LAN segment',
  'lan.vlanSegmentation': 'LAN segmentation by 802.1Q VLAN',
  'lan.dhcpServer': 'on-box DHCP server',
  'lan.dhcpReservation': 'static DHCP reservation',
  'lan.segmentIsolation': 'guest segment isolated from the other segments',
  'policy.statefulFirewall': 'stateful firewall policy',
  'policy.zoneModel': 'named security zones',
  'policy.portForward': 'inbound port publication (destination NAT)',
  'policy.interSegmentControl': 'control of traffic between LAN segments',
  'policy.icmpControl': 'explicit control of ICMP from the WAN',
  'vpn.ipsecSiteToSite': 'site-to-site IPsec tunnel',
  'vpn.ikev2': 'IKEv2 key exchange',
  'mgmt.serviceRestriction': 'restriction of the management services by source address',
  'mgmt.localUsers': 'provisioning of local administrator accounts',
  'mgmt.snmpV3': 'SNMP v3 (authenticated and encrypted)',
  'qos.shaping': 'bandwidth shaping',
  'qos.perSegmentPriority': 'per-segment queue priority',
  'safety.onDeviceDeadMan': 'dead-man restore scheduled on the device itself',
  'safety.atomicCommit': 'all-or-nothing commit of a staged configuration',
  'safety.noRebootApply': 'applying the configuration without a reboot',
  'safety.structuredDiff': 'structured (line-level) configuration diff',
};

/**
 * The join with `device.ts`. A feature listed here additionally requires those
 * `DeviceCapabilities` flags to be TRUE on the resolved driver.
 *
 * Only the `safety.*` features have an honest mapping today, and that is stated
 * rather than papered over: `DeviceCapabilities` describes what the DRIVER can
 * do (transports, formats, write paths), not the appliance's feature set. The
 * per-brand `IntentSupport` matrix carries the other half. Inventing a
 * `canDoVlans` flag here would have meant editing `device.ts` — a file this
 * milestone does not own — and would have put the same knowledge in two places
 * that can disagree.
 *
 * `canPushConfig` is deliberately required by nothing. Compilation produces a
 * document; only `change_jobs` writes to hardware (D3), and that path runs its
 * own capability gate at apply time.
 */
export const FEATURE_REQUIRES_FLAGS: Readonly<
  Partial<Record<IntentFeature, readonly DeviceCapabilityFlag[]>>
> = {
  'safety.onDeviceDeadMan': ['canScheduleOnDevice'],
  'safety.atomicCommit': ['requiresExplicitCommit'],
  'safety.structuredDiff': ['supportsStructuredDiff'],
};

/** Flags that must be FALSE. `requiresRebootToApply` is the DrayTek `.cfg`
 *  restore, and an intent that forbids an outage must refuse that box. */
export const FEATURE_FORBIDS_FLAGS: Readonly<
  Partial<Record<IntentFeature, readonly DeviceCapabilityFlag[]>>
> = {
  'safety.noRebootApply': ['requiresRebootToApply'],
};

/** Per-brand answer to every feature. */
export type IntentSupport = Record<IntentFeature, boolean>;

/**
 * Every feature `false`. Brand profiles spread this and turn on ONLY what
 * somebody wrote a renderer for and stands behind — the same discipline, and
 * for the same reason, as `NO_CAPABILITIES` in `device.ts`.
 *
 * Frozen: a profile that mutated the shared object instead of spreading it
 * would grant its answers to every other brand.
 */
export const NO_INTENT_SUPPORT: Readonly<IntentSupport> = Object.freeze(
  INTENT_FEATURES.reduce((acc, f) => {
    acc[f] = false;
    return acc;
  }, {} as IntentSupport),
);

// ============================================================================
// Which features an intent actually uses
// ============================================================================

/** One requirement, with the place in the intent that created it — so a refusal
 *  points at the line the operator wrote, not at the whole document. */
export interface IntentFeatureUse {
  feature: IntentFeature;
  /** Dotted path into the intent, e.g. `lans[1].vlanId`. */
  path: string;
}

/**
 * The single source of truth for "what does this intent need".
 *
 * Pure, deterministic, no I/O, no device: this is the function that makes
 * "fail at compile time, before any network access" possible at all. The server
 * calls it from `capabilityCheck`, and the client calls it to grey out the
 * brands a half-written intent has already excluded.
 */
export function featuresRequiredBy(intent: SiteIntentDocument): IntentFeatureUse[] {
  const uses: IntentFeatureUse[] = [];
  const add = (feature: IntentFeature, path: string): void => {
    if (!uses.some((u) => u.feature === feature)) uses.push({ feature, path });
  };

  intent.wan.forEach((w, i) => {
    add(`wan.${w.mode}` as IntentFeature, `wan[${i}].mode`);
    if (w.vlanId !== null) add('wan.vlanTag', `wan[${i}].vlanId`);
  });
  if (intent.wan.length > 1) add('wan.multiUplink', 'wan');

  if (intent.lans.length > 1) add('lan.multiSegment', 'lans');
  intent.lans.forEach((l, i) => {
    if (l.vlanId !== null) add('lan.vlanSegmentation', `lans[${i}].vlanId`);
    if (l.dhcp) {
      add('lan.dhcpServer', `lans[${i}].dhcp`);
      if (l.dhcp.reservations.length > 0) add('lan.dhcpReservation', `lans[${i}].dhcp.reservations`);
    }
    if (l.isolated) add('lan.segmentIsolation', `lans[${i}].isolated`);
  });

  // Every intent asks for a stateful firewall: `defaultInbound` is drop or
  // reject, there is no third value, and a box that cannot express that must
  // never receive a site build.
  add('policy.statefulFirewall', 'policy.defaultInbound');
  if (intent.policy.publish.length > 0) add('policy.portForward', 'policy.publish');
  if (intent.policy.zones.length > 0) add('policy.zoneModel', 'policy.zones');
  if (intent.policy.interSegment === 'deny' && intent.lans.length > 1) {
    add('policy.interSegmentControl', 'policy.interSegment');
  }
  if (intent.policy.allowPingFromWan) add('policy.icmpControl', 'policy.allowPingFromWan');

  intent.vpn.forEach((v, i) => {
    add('vpn.ipsecSiteToSite', `vpn[${i}]`);
    if (v.exchangeMode === 'ike2') add('vpn.ikev2', `vpn[${i}].exchangeMode`);
  });

  if (intent.management.services.some((s) => s.enabled && s.allowedFrom.length > 0)) {
    add('mgmt.serviceRestriction', 'management.services');
  }
  if (intent.management.localUsers.length > 0) add('mgmt.localUsers', 'management.localUsers');
  if (intent.management.snmp?.version === 'v3') add('mgmt.snmpV3', 'management.snmp.version');

  if (intent.qos) {
    add('qos.shaping', 'qos');
    if (intent.qos.segments.some((s) => s.priority !== null)) {
      add('qos.perSegmentPriority', 'qos.segments');
    }
  }

  if (intent.safety.requireOnDeviceDeadMan) {
    add('safety.onDeviceDeadMan', 'safety.requireOnDeviceDeadMan');
  }
  if (intent.safety.requireAtomicCommit) add('safety.atomicCommit', 'safety.requireAtomicCommit');
  if (intent.safety.forbidRebootToApply) add('safety.noRebootApply', 'safety.forbidRebootToApply');
  if (intent.safety.requireStructuredDiff) {
    add('safety.structuredDiff', 'safety.requireStructuredDiff');
  }

  return uses;
}

// ============================================================================
// The refusal
// ============================================================================

export const CAPABILITY_GAP_REASONS = [
  /** The brand profile says this family cannot express the feature at all. */
  'family_cannot_express',
  /** A `DeviceCapabilities` flag the feature requires is false. */
  'driver_capability_missing',
  /** A `DeviceCapabilities` flag the feature forbids is true. */
  'driver_capability_conflicts',
] as const;
export type CapabilityGapReason = (typeof CAPABILITY_GAP_REASONS)[number];

/** One reason a compilation was refused, in a shape the UI can put in a table
 *  and the database can store a row of. */
export interface CapabilityGap {
  feature: IntentFeature;
  featureLabel: string;
  brand: DeviceBrand;
  family: DeviceFamily;
  reason: CapabilityGapReason;
  /** The `DeviceCapabilities` flag involved, when the reason names one. */
  capabilityFlag: DeviceCapabilityFlag | null;
  /** Where in the intent the requirement came from. */
  intentPath: string;
  /** Vendor-specific explanation from the brand profile, when it has one. */
  note: string | null;
}

/**
 * The sentence an operator reads. It names the CAPABILITY and the BRAND,
 * because "compilation failed" without those two words is precisely why people
 * go back to asking the senior engineer.
 */
export function describeGap(gap: CapabilityGap): string {
  const head = `${gap.brand}/${gap.family} cannot satisfy "${gap.feature}" (${gap.featureLabel})`;
  const note = gap.note ? ` — ${gap.note}` : '';
  switch (gap.reason) {
    case 'family_cannot_express':
      return `${head}: the family has no way to express it${note} [${gap.intentPath}]`;
    case 'driver_capability_missing':
      return `${head}: the driver declares ${gap.capabilityFlag} = false${note} [${gap.intentPath}]`;
    case 'driver_capability_conflicts':
      return `${head}: the driver declares ${gap.capabilityFlag} = true${note} [${gap.intentPath}]`;
  }
}

export interface CapabilityVerdict {
  brand: DeviceBrand;
  family: DeviceFamily;
  ok: boolean;
  /** Everything the intent asked of this family. */
  required: IntentFeatureUse[];
  /** Everything it cannot do. Empty exactly when `ok`. */
  gaps: CapabilityGap[];
}

/** The compiled artefact formats, one per dialect. */
export const ARTIFACT_FORMATS = [
  'routeros_script',
  'draytek_cli',
  'zyxel_zld_cli',
  'sonicos_rest',
] as const;
export type ArtifactFormat = (typeof ARTIFACT_FORMATS)[number];

/** The full support matrix, for the UI panel risk R2 demands: brand coverage
 *  has to be VISIBLE, not implied. */
export interface BrandCoverageRow {
  brand: DeviceBrand;
  family: DeviceFamily;
  artifactFormat: ArtifactFormat | null;
  support: IntentSupport;
  capabilities: Pick<
    DeviceCapabilities,
    | 'configFormat'
    | 'applyGranularity'
    | 'supportsStructuredDiff'
    | 'requiresExplicitCommit'
    | 'requiresRebootToApply'
    | 'canScheduleOnDevice'
  >;
  notes: string[];
}
