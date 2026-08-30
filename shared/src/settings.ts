// ============================================================================
// @obliwan/shared — hierarchical settings contract
// ============================================================================
//
// A setting is a NUMERIC value resolved along the inheritance chain
// global → tenant → group chain → device (see `settings.service.ts`).
// `scope` is 'global' | 'group' | 'device' (arbitrage A4); `HARDCODED_DEFAULTS`
// is the floor used when nothing is stored at any level.
//
// Non-numeric preferences (theme, language, toast position) live on the USER,
// not here — see `UserPreferences` in types.ts. Do not add string settings to
// this table without changing `SettingValue.value` and every consumer.
//
// Values that are NOT settings and must never move here: credentials (vault),
// the SSO configuration and the global kill-switch (`app_config`).

export const SETTINGS_KEYS = {
  // ── Notifications ──────────────────────────────────────────────────────
  /** Minimum seconds between two identical notifications for the same key. */
  NOTIFICATION_COOLDOWN: 'notification_cooldown',

  // ── Reachability / presence (M2, decision D4) ──────────────────────────
  /** Seconds a PPP session may stay down before the device is declared DOWN. */
  PRESENCE_GRACE_PERIOD: 'presence_grace_period',
  /** Milliseconds before a transport connection attempt is abandoned. */
  DEVICE_TIMEOUT: 'device_timeout',

  // ── SNMP polling (M3) ──────────────────────────────────────────────────
  SNMP_POLL_INTERVAL: 'snmp_poll_interval',
  SNMP_TIMEOUT: 'snmp_timeout',
  SNMP_RETRIES: 'snmp_retries',

  // ── Configuration collection & drift (M4) ──────────────────────────────
  /** Minutes between two config snapshots of the same device. */
  SNAPSHOT_INTERVAL: 'snapshot_interval',
  /** Minutes between two drift runs. */
  DRIFT_INTERVAL: 'drift_interval',

  // ── Safe-Apply (M6, killer K1) ─────────────────────────────────────────
  /** Seconds the on-device dead-man waits before self-rollback. */
  COMMIT_CONFIRM_TIMEOUT: 'commit_confirm_timeout',
  /** Seconds of post-apply soak before the dead-man is disarmed. */
  APPLY_SOAK_SECONDS: 'apply_soak_seconds',
  /** Maximum change jobs executed concurrently across the fleet. */
  MAX_CONCURRENT_JOBS: 'max_concurrent_jobs',

  // ── Retention ──────────────────────────────────────────────────────────
  /** Days of raw interface samples kept before rollups only. */
  TIMESERIES_RETENTION_DAYS: 'timeseries_retention_days',
  /** Days of config snapshots kept (deduplicated by NCM hash). */
  CONFIG_RETENTION_DAYS: 'config_retention_days',
  /** Days of audit and command-audit rows kept. */
  AUDIT_RETENTION_DAYS: 'audit_retention_days',
} as const;

export type SettingsKey = (typeof SETTINGS_KEYS)[keyof typeof SETTINGS_KEYS];

export const SETTING_CATEGORIES = [
  'notifications',
  'reachability',
  'snmp',
  'configuration',
  'change',
  'retention',
] as const;

export type SettingCategory = (typeof SETTING_CATEGORIES)[number];

export interface SettingDefinition {
  key: SettingsKey;
  category: SettingCategory;
  label: string;
  description: string;
  type: 'number';
  unit: string;
  default: number;
  min: number;
  max: number;
}

export const SETTINGS_DEFINITIONS: SettingDefinition[] = [
  {
    key: SETTINGS_KEYS.NOTIFICATION_COOLDOWN,
    category: 'notifications',
    label: 'Notification cooldown',
    description: 'Minimum time between repeated notifications for the same event',
    type: 'number',
    unit: 'seconds',
    default: 300,
    min: 0,
    max: 86400,
  },
  {
    key: SETTINGS_KEYS.PRESENCE_GRACE_PERIOD,
    category: 'reachability',
    label: 'Presence grace period',
    description: 'How long a PPP session may stay down before the device is reported DOWN',
    type: 'number',
    unit: 'seconds',
    default: 120,
    min: 0,
    max: 3600,
  },
  {
    key: SETTINGS_KEYS.DEVICE_TIMEOUT,
    category: 'reachability',
    label: 'Device timeout',
    description: 'Time before a transport connection attempt is abandoned',
    type: 'number',
    unit: 'ms',
    default: 15000,
    min: 1000,
    max: 120000,
  },
  {
    key: SETTINGS_KEYS.SNMP_POLL_INTERVAL,
    category: 'snmp',
    label: 'SNMP poll interval',
    description: 'How often interface counters are polled',
    type: 'number',
    unit: 'seconds',
    default: 60,
    min: 10,
    max: 3600,
  },
  {
    key: SETTINGS_KEYS.SNMP_TIMEOUT,
    category: 'snmp',
    label: 'SNMP timeout',
    description: 'Time before an SNMP request is considered lost',
    type: 'number',
    unit: 'ms',
    default: 5000,
    min: 500,
    max: 60000,
  },
  {
    key: SETTINGS_KEYS.SNMP_RETRIES,
    category: 'snmp',
    label: 'SNMP retries',
    description: 'Retries per SNMP request before the poll is marked failed',
    type: 'number',
    unit: 'retries',
    default: 2,
    min: 0,
    max: 10,
  },
  {
    key: SETTINGS_KEYS.SNAPSHOT_INTERVAL,
    category: 'configuration',
    label: 'Snapshot interval',
    description: 'How often a device configuration is collected and normalized',
    type: 'number',
    unit: 'minutes',
    default: 1440,
    min: 5,
    max: 43200,
  },
  {
    key: SETTINGS_KEYS.DRIFT_INTERVAL,
    category: 'configuration',
    label: 'Drift check interval',
    description: 'How often the observed NCM is compared to the desired NCM',
    type: 'number',
    unit: 'minutes',
    default: 1440,
    min: 5,
    max: 43200,
  },
  {
    key: SETTINGS_KEYS.COMMIT_CONFIRM_TIMEOUT,
    category: 'change',
    label: 'Commit-confirm timeout',
    description: 'How long the on-device dead-man waits before rolling back on its own',
    type: 'number',
    unit: 'seconds',
    default: 600,
    min: 60,
    max: 3600,
  },
  {
    key: SETTINGS_KEYS.APPLY_SOAK_SECONDS,
    category: 'change',
    label: 'Post-apply soak',
    description: 'Observation window after a successful apply before the dead-man is disarmed',
    type: 'number',
    unit: 'seconds',
    default: 300,
    min: 30,
    max: 3600,
  },
  {
    key: SETTINGS_KEYS.MAX_CONCURRENT_JOBS,
    category: 'change',
    label: 'Max concurrent change jobs',
    description: 'Upper bound on change jobs running at the same time across the fleet',
    type: 'number',
    unit: 'jobs',
    default: 5,
    min: 1,
    max: 100,
  },
  {
    key: SETTINGS_KEYS.TIMESERIES_RETENTION_DAYS,
    category: 'retention',
    label: 'Time-series retention',
    description: 'How long raw interface samples are kept before only rollups remain',
    type: 'number',
    unit: 'days',
    default: 90,
    min: 1,
    max: 3650,
  },
  {
    key: SETTINGS_KEYS.CONFIG_RETENTION_DAYS,
    category: 'retention',
    label: 'Configuration retention',
    description: 'How long configuration snapshots are kept',
    type: 'number',
    unit: 'days',
    default: 365,
    min: 1,
    max: 3650,
  },
  {
    key: SETTINGS_KEYS.AUDIT_RETENTION_DAYS,
    category: 'retention',
    label: 'Audit retention',
    description: 'How long audit log and command audit entries are kept',
    type: 'number',
    unit: 'days',
    default: 730,
    min: 30,
    max: 3650,
  },
];

export const HARDCODED_DEFAULTS: Record<SettingsKey, number> = {
  [SETTINGS_KEYS.NOTIFICATION_COOLDOWN]: 300,
  [SETTINGS_KEYS.PRESENCE_GRACE_PERIOD]: 120,
  [SETTINGS_KEYS.DEVICE_TIMEOUT]: 15000,
  [SETTINGS_KEYS.SNMP_POLL_INTERVAL]: 60,
  [SETTINGS_KEYS.SNMP_TIMEOUT]: 5000,
  [SETTINGS_KEYS.SNMP_RETRIES]: 2,
  [SETTINGS_KEYS.SNAPSHOT_INTERVAL]: 1440,
  [SETTINGS_KEYS.DRIFT_INTERVAL]: 1440,
  [SETTINGS_KEYS.COMMIT_CONFIRM_TIMEOUT]: 600,
  [SETTINGS_KEYS.APPLY_SOAK_SECONDS]: 300,
  [SETTINGS_KEYS.MAX_CONCURRENT_JOBS]: 5,
  [SETTINGS_KEYS.TIMESERIES_RETENTION_DAYS]: 90,
  [SETTINGS_KEYS.CONFIG_RETENTION_DAYS]: 365,
  [SETTINGS_KEYS.AUDIT_RETENTION_DAYS]: 730,
};

const DEFINITION_BY_KEY = new Map<string, SettingDefinition>(
  SETTINGS_DEFINITIONS.map((d) => [d.key, d]),
);

export function isSettingsKey(value: unknown): value is SettingsKey {
  return typeof value === 'string' && DEFINITION_BY_KEY.has(value);
}

export function getSettingDefinition(key: SettingsKey): SettingDefinition | undefined {
  return DEFINITION_BY_KEY.get(key);
}

/** Clamps a candidate value into the definition bounds; falls back to the default. */
export function clampSetting(key: SettingsKey, value: number): number {
  const def = DEFINITION_BY_KEY.get(key);
  if (!def) return value;
  if (!Number.isFinite(value)) return def.default;
  return Math.min(def.max, Math.max(def.min, value));
}
