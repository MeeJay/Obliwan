// ============================================================================
// @obliwan/shared — RBAC capability vocabulary
// ============================================================================
//
// THIS FILE IS THE SINGLE SOURCE OF TRUTH for what a user may do in ObliWAN
// (decision D7 / arbitrage A4). Every other place that names a capability —
// the `permission_sets` table, `team_permissions.capabilities`, the RBAC
// middleware, the Obligate SSO payload, the admin UI — MUST import from here
// and never re-declare its own list.
//
// Naming convention: `<domain>.<verb>`. Values are persisted in the database
// and exchanged with Obligate: they are a wire format. NEVER rename a value;
// add a new one and migrate.
//
// Not all of these are wired in M1 — the vocabulary is laid down once, up
// front, because that is the only moment it is free.

export const CAPABILITIES = {
  // ── Fleet / inventory (M2) ─────────────────────────────────────────────
  /** See sites, devices, transports (metadata only — never configuration). */
  DEVICE_READ: 'device.read',
  /** Create / edit / delete sites, devices and their transport records. */
  DEVICE_WRITE: 'device.write',
  /** Review the CHR discovery quarantine and bind a PPP session to a device. */
  DEVICE_DISCOVER: 'device.discover',

  // ── Configuration (M4) ─────────────────────────────────────────────────
  //
  // Risk R10: CONFIG_READ is deliberately DISTINCT from DEVICE_READ. A config
  // snapshot may carry residual sensitive material (PSK, PPP secrets, IPsec
  // keys) even with `show-sensitive=no`; seeing the fleet must not imply
  // seeing its configuration.
  /** Read config snapshots, the NCM and semantic diffs. */
  CONFIG_READ: 'config.read',
  /** Author normalization rules and edit the desired NCM. Does NOT push. */
  CONFIG_WRITE: 'config.write',

  // ── Templates & intent (M5 / K4) ───────────────────────────────────────
  /** Read templates, partials, revisions and resolved variables. */
  TEMPLATE_READ: 'template.read',
  /**
   * Author / publish templates and partials.
   * Risk R6: this capability is the security boundary in front of the
   * Nunjucks renderer, which runs on the host holding the fleet credentials.
   */
  TEMPLATE_WRITE: 'template.write',

  // ── Plan & change (M5 / M6 — decision D3) ──────────────────────────────
  /** Compile a plan (read-only: computes PlanOp[], touches no device). */
  PLAN_CREATE: 'plan.create',
  /** Enqueue a change_job that actually writes to an equipment. */
  CHANGE_APPLY: 'change.apply',
  /** Four-eyes approval of a plan, and override of a Management-Path Guard veto. */
  CHANGE_APPROVE: 'change.approve',
  /** Start / pause / abort a wave rollout (K3). */
  ROLLOUT_MANAGE: 'rollout.manage',

  // ── Drift & query (M4 / M8 / M9) ───────────────────────────────────────
  /** Read drift runs, findings and their attribution. */
  DRIFT_READ: 'drift.read',
  /** Acknowledge / ignore a drift finding. */
  DRIFT_MANAGE: 'drift.manage',
  /** Run Fleet Query DSL queries and save them (K5). */
  QUERY_RUN: 'query.run',

  // ── SNMP & telemetry (M3) ──────────────────────────────────────────────
  /** Read interfaces, counters, time series and thresholds. */
  SNMP_READ: 'snmp.read',
  /** Manage SNMP targets, communities / v3 users, discovery and thresholds. */
  SNMP_ADMIN: 'snmp.admin',

  // ── ACS TR-069 (M10) ───────────────────────────────────────────────────
  /** Manage CPEs, the CWMP task queue, parameter maps and firmware files. */
  ACS_ADMIN: 'acs.admin',

  // ── Secrets (M2 — arbitrage A3) ────────────────────────────────────────
  /** Create / rotate / delete credentials in the vault. Never reveals them. */
  CREDENTIAL_MANAGE: 'credential.manage',
  /**
   * Reveal a stored secret in clear. Deliberately separate from
   * CREDENTIAL_MANAGE: rotating is an operator act, revealing is not.
   */
  SECRET_READ: 'secret.read',

  // ── Administration (inherited from the Obli* base) ─────────────────────
  /** Create / edit / delete / move device groups. */
  GROUP_WRITE: 'group.write',
  /** Manage users, teams and permission sets. */
  USERS_MANAGE: 'users.manage',
  /** Create / edit / delete tenants and their memberships. */
  TENANTS_MANAGE: 'tenants.manage',
  /** Change global and scoped settings, SMTP servers, SSO and the kill-switch. */
  SETTINGS_MANAGE: 'settings.manage',
  /** Manage notification channels and bindings. */
  NOTIFICATIONS_MANAGE: 'notifications.manage',
  /** Read the append-only audit log and the command audit. */
  AUDIT_READ: 'audit.read',
  /** Export a tenant (templates, inventory, variables) to a portable bundle. */
  EXPORT_RUN: 'export.run',
  /** Import a bundle, including conflict resolution. */
  IMPORT_RUN: 'import.run',
} as const;

export type Capability = (typeof CAPABILITIES)[keyof typeof CAPABILITIES];

export const CAPABILITY_DOMAINS = [
  'fleet',
  'config',
  'template',
  'change',
  'drift',
  'telemetry',
  'acs',
  'secrets',
  'admin',
] as const;

export type CapabilityDomain = (typeof CAPABILITY_DOMAINS)[number];

export interface CapabilityInfo {
  key: Capability;
  domain: CapabilityDomain;
  label: string;
  description: string;
  /**
   * True when granting this capability lets the holder change the state of a
   * physical equipment, or read material that must not leak. The admin UI
   * flags these; read-only permission-set seeds keep them out.
   */
  sensitive: boolean;
}

/**
 * Full catalogue, ordered for display. `permissionSet.service` serves this
 * list verbatim — it must not maintain a copy of its own.
 */
export const CAPABILITY_CATALOG: readonly CapabilityInfo[] = [
  { key: CAPABILITIES.DEVICE_READ, domain: 'fleet', label: 'Read fleet', description: 'View sites, devices and transports (metadata only)', sensitive: false },
  { key: CAPABILITIES.DEVICE_WRITE, domain: 'fleet', label: 'Manage fleet', description: 'Create, edit and delete sites, devices and transports', sensitive: false },
  { key: CAPABILITIES.DEVICE_DISCOVER, domain: 'fleet', label: 'Bind discoveries', description: 'Review the PPP discovery quarantine and bind devices', sensitive: false },

  { key: CAPABILITIES.CONFIG_READ, domain: 'config', label: 'Read configuration', description: 'View config snapshots, the NCM and semantic diffs', sensitive: true },
  { key: CAPABILITIES.CONFIG_WRITE, domain: 'config', label: 'Edit configuration', description: 'Author normalization rules and the desired NCM', sensitive: false },

  { key: CAPABILITIES.TEMPLATE_READ, domain: 'template', label: 'Read templates', description: 'View templates, partials, revisions and variables', sensitive: false },
  { key: CAPABILITIES.TEMPLATE_WRITE, domain: 'template', label: 'Author templates', description: 'Write and publish templates and partials', sensitive: true },

  { key: CAPABILITIES.PLAN_CREATE, domain: 'change', label: 'Compile plans', description: 'Compute a change plan without touching any equipment', sensitive: false },
  { key: CAPABILITIES.CHANGE_APPLY, domain: 'change', label: 'Apply changes', description: 'Enqueue a change job that writes to an equipment', sensitive: true },
  { key: CAPABILITIES.CHANGE_APPROVE, domain: 'change', label: 'Approve changes', description: 'Four-eyes approval and Management-Path Guard override', sensitive: true },
  { key: CAPABILITIES.ROLLOUT_MANAGE, domain: 'change', label: 'Manage rollouts', description: 'Start, pause and abort wave rollouts', sensitive: true },

  { key: CAPABILITIES.DRIFT_READ, domain: 'drift', label: 'Read drift', description: 'View drift runs, findings and their attribution', sensitive: false },
  { key: CAPABILITIES.DRIFT_MANAGE, domain: 'drift', label: 'Manage drift', description: 'Acknowledge and ignore drift findings', sensitive: false },
  { key: CAPABILITIES.QUERY_RUN, domain: 'drift', label: 'Run fleet queries', description: 'Execute and save Fleet Query DSL queries', sensitive: false },

  { key: CAPABILITIES.SNMP_READ, domain: 'telemetry', label: 'Read telemetry', description: 'View interfaces, counters, time series and thresholds', sensitive: false },
  { key: CAPABILITIES.SNMP_ADMIN, domain: 'telemetry', label: 'Manage SNMP', description: 'Manage SNMP targets, credentials and thresholds', sensitive: true },

  { key: CAPABILITIES.ACS_ADMIN, domain: 'acs', label: 'Manage ACS', description: 'Manage CPEs, CWMP tasks, parameter maps and firmware', sensitive: true },

  { key: CAPABILITIES.CREDENTIAL_MANAGE, domain: 'secrets', label: 'Manage credentials', description: 'Create, rotate and delete vault credentials', sensitive: true },
  { key: CAPABILITIES.SECRET_READ, domain: 'secrets', label: 'Reveal secrets', description: 'Display a stored secret in clear text', sensitive: true },

  { key: CAPABILITIES.GROUP_WRITE, domain: 'admin', label: 'Manage groups', description: 'Create, edit, delete and move device groups', sensitive: false },
  { key: CAPABILITIES.USERS_MANAGE, domain: 'admin', label: 'Manage users', description: 'Manage users, teams and permission sets', sensitive: true },
  { key: CAPABILITIES.TENANTS_MANAGE, domain: 'admin', label: 'Manage tenants', description: 'Create, edit and delete tenants and memberships', sensitive: true },
  { key: CAPABILITIES.SETTINGS_MANAGE, domain: 'admin', label: 'Manage settings', description: 'Change settings, SMTP, SSO and the global kill-switch', sensitive: true },
  { key: CAPABILITIES.NOTIFICATIONS_MANAGE, domain: 'admin', label: 'Manage notifications', description: 'Manage notification channels and bindings', sensitive: false },
  { key: CAPABILITIES.AUDIT_READ, domain: 'admin', label: 'Read audit', description: 'Read the audit log and the command audit', sensitive: true },
  { key: CAPABILITIES.EXPORT_RUN, domain: 'admin', label: 'Export', description: 'Export a tenant to a portable bundle', sensitive: true },
  { key: CAPABILITIES.IMPORT_RUN, domain: 'admin', label: 'Import', description: 'Import a bundle and resolve conflicts', sensitive: true },
];

export const ALL_CAPABILITIES: Capability[] = CAPABILITY_CATALOG.map((c) => c.key);

const CAPABILITY_SET: ReadonlySet<string> = new Set<string>(ALL_CAPABILITIES);

/** Narrowing guard for values coming from the DB, the API or Obligate. */
export function isCapability(value: unknown): value is Capability {
  return typeof value === 'string' && CAPABILITY_SET.has(value);
}

/** Drops anything unknown — never trust a persisted or federated list blindly. */
export function sanitizeCapabilities(values: readonly unknown[]): Capability[] {
  return values.filter(isCapability);
}

/**
 * Capabilities that cannot usefully be held alone.
 *
 * The built-in sets are coherent, but a hand-made permission set granting
 * CHANGE_APPLY without PLAN_CREATE produces a grant that can enqueue a change
 * and then cannot read the queue, the job, its steps or the kill-switch state —
 * every one of those is PLAN_CREATE. Worse on the rollout screen: the blast
 * radius is computed per device through PLAN_CREATE routes, so each device
 * answers 403, the safety net reads "not established", and fail-closed turns the
 * whole fleet DEGRADED. Honest, and unusable.
 *
 * Expressed as an implication rather than documented as a caveat: a rule nobody
 * can violate beats a rule everybody must remember.
 */
export const CAPABILITY_IMPLIES: Readonly<Partial<Record<Capability, readonly Capability[]>>> = {
  // Applying presupposes seeing what you applied.
  [CAPABILITIES.CHANGE_APPLY]: [CAPABILITIES.PLAN_CREATE],
  // Overriding the guard presupposes being able to read the verdict you overrule.
  [CAPABILITIES.CHANGE_APPROVE]: [CAPABILITIES.PLAN_CREATE],
  // A rollout is a batch of change jobs.
  [CAPABILITIES.ROLLOUT_MANAGE]: [CAPABILITIES.PLAN_CREATE, CAPABILITIES.CHANGE_APPLY],
  // Writing a config without reading it is a diff against nothing.
  [CAPABILITIES.CONFIG_WRITE]: [CAPABILITIES.CONFIG_READ],
  [CAPABILITIES.TEMPLATE_WRITE]: [CAPABILITIES.TEMPLATE_READ],
  [CAPABILITIES.DRIFT_MANAGE]: [CAPABILITIES.DRIFT_READ],
  [CAPABILITIES.SNMP_ADMIN]: [CAPABILITIES.SNMP_READ],
  // Revealing a secret presupposes being allowed to manage the credential it
  // belongs to. The reverse is deliberately NOT true: rotating a password is an
  // ordinary operational act, reading one is not (§7 / A3).
  [CAPABILITIES.SECRET_READ]: [CAPABILITIES.CREDENTIAL_MANAGE],
};

/**
 * Closes a capability list under `CAPABILITY_IMPLIES`.
 *
 * Call this where capabilities are RESOLVED for a request, not where they are
 * stored: the stored grant stays exactly what an administrator typed, and the
 * expansion is what the request is evaluated against.
 */
export function expandCapabilities(values: readonly Capability[]): Capability[] {
  const held = new Set<Capability>(values);
  // Fixed point rather than one pass: an implication may itself imply.
  for (let changed = true; changed; ) {
    changed = false;
    for (const c of [...held]) {
      for (const implied of CAPABILITY_IMPLIES[c] ?? []) {
        if (!held.has(implied)) { held.add(implied); changed = true; }
      }
    }
  }
  return ALL_CAPABILITIES.filter((c) => held.has(c));
}

export function capabilitiesByDomain(domain: CapabilityDomain): CapabilityInfo[] {
  return CAPABILITY_CATALOG.filter((c) => c.domain === domain);
}

/**
 * Seed material for `permission_sets` (migration 001). Admins implicitly hold
 * every capability and are never matched against these sets.
 */
export const BUILTIN_PERMISSION_SETS: ReadonlyArray<{
  slug: string;
  name: string;
  capabilities: Capability[];
}> = [
  {
    slug: 'viewer',
    name: 'Viewer',
    capabilities: [
      CAPABILITIES.DEVICE_READ,
      CAPABILITIES.TEMPLATE_READ,
      CAPABILITIES.DRIFT_READ,
      CAPABILITIES.SNMP_READ,
    ],
  },
  {
    slug: 'operator',
    name: 'Operator',
    capabilities: [
      CAPABILITIES.DEVICE_READ,
      CAPABILITIES.DEVICE_WRITE,
      CAPABILITIES.DEVICE_DISCOVER,
      CAPABILITIES.CONFIG_READ,
      CAPABILITIES.TEMPLATE_READ,
      CAPABILITIES.PLAN_CREATE,
      CAPABILITIES.DRIFT_READ,
      CAPABILITIES.DRIFT_MANAGE,
      CAPABILITIES.QUERY_RUN,
      CAPABILITIES.SNMP_READ,
    ],
  },
  {
    slug: 'engineer',
    name: 'Network engineer',
    capabilities: [
      CAPABILITIES.DEVICE_READ,
      CAPABILITIES.DEVICE_WRITE,
      CAPABILITIES.DEVICE_DISCOVER,
      CAPABILITIES.CONFIG_READ,
      CAPABILITIES.CONFIG_WRITE,
      CAPABILITIES.TEMPLATE_READ,
      CAPABILITIES.TEMPLATE_WRITE,
      CAPABILITIES.PLAN_CREATE,
      CAPABILITIES.CHANGE_APPLY,
      CAPABILITIES.ROLLOUT_MANAGE,
      CAPABILITIES.DRIFT_READ,
      CAPABILITIES.DRIFT_MANAGE,
      CAPABILITIES.QUERY_RUN,
      CAPABILITIES.SNMP_READ,
      CAPABILITIES.SNMP_ADMIN,
      CAPABILITIES.CREDENTIAL_MANAGE,
    ],
  },
];
