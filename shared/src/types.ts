// ============================================================================
// @obliwan/shared — core DTOs shared by server and client
// ============================================================================
//
// Scope of this file: the M1 core contract only — identity, tenants, device
// groups, settings envelope, notifications, SMTP, app config, teams/RBAC.
//
// Domain models for later milestones do NOT belong here:
//   ncm/       (M4)  NcmDocument, resources, semantic keys, PlanOp
//   intent/    (M8+) IntentDocument
//   device.ts  (M2)  DeviceBrand, TransportKind, DeviceCapabilities
//   telemetry.ts (M3) InterfaceSample, ReachabilityVerdict
// They are created by their own milestone, not stubbed here.

import type { SettingsKey } from './settings';

// ============================================
// User types
// ============================================
export const USER_ROLES = ['admin', 'user'] as const;
export type UserRole = (typeof USER_ROLES)[number];

/** The four Obli Design themes. Persisted client-side under the `ow-theme` key. */
export type AppTheme = 'obli-operator' | 'obli-daylight' | 'modern' | 'neon';

export const APP_THEMES: readonly AppTheme[] = [
  'obli-operator',
  'obli-daylight',
  'modern',
  'neon',
];

export interface UserPreferences {
  toastEnabled: boolean;
  toastPosition: 'top-center' | 'bottom-right';
  multiTenantNotificationsEnabled?: boolean;
  preferredTheme?: AppTheme;
  anonymousMode?: boolean;
}

/** Shape of a live alert as returned by the server. */
export interface LiveAlertData {
  id: number;
  tenantId: number;
  tenantName?: string;
  severity: 'down' | 'up' | 'warning' | 'info';
  title: string;
  message: string;
  navigateTo: string | null;
  stableKey: string | null;
  read: boolean;
  createdAt: string;
}

export interface User {
  id: number;
  username: string;
  displayName: string | null;
  role: UserRole;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
  preferences?: UserPreferences | null;
  email?: string | null;
  preferredLanguage: string;
  enrollmentVersion: number;
  totpEnabled?: boolean;
  emailOtpEnabled?: boolean;
  foreignSource?: string | null;
  /** Profile picture as base64 data URI or remote URL — synced from Obligate when SSO is used. */
  avatar?: string | null;
}

export interface UserWithPassword extends User {
  /** Nullable for SSO-provisioned users, which have no local password. */
  passwordHash: string | null;
}

// ============================================
// Auth / session types
// ============================================
export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  user: User;
  /** Set when the credentials were valid but a second factor is still required. */
  twoFactorRequired?: boolean;
}

/** Second-factor state of the current user. */
export interface TwoFactorStatus {
  totpEnabled: boolean;
  emailOtpEnabled: boolean;
  /** True when app config forces 2FA and the user has not enrolled yet. */
  enrollmentRequired: boolean;
}

/** One active browser session of the current user. */
export interface SessionInfo {
  id: string;
  current: boolean;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
  expiresAt: string;
}

/**
 * Obligate SSO enrollment stamp. `enrollmentVersion` is bumped by Obligate
 * when the federated profile changes; a mismatch forces a resync at login.
 */
export interface EnrollmentState {
  foreignSource: string | null;
  foreignId: string | null;
  foreignSourceUrl: string | null;
  enrollmentVersion: number;
}

// ============================================
// Tenant types
// ============================================
export interface Tenant {
  id: number;
  name: string;
  slug: string;
  createdAt: string;
  updatedAt: string;
}

export interface TenantMembership {
  tenantId: number;
  userId: number;
  role: 'admin' | 'member';
}

export interface TenantWithRole extends Tenant {
  role: 'admin' | 'member';
}

export interface UserTenantAssignment {
  tenantId: number;
  tenantName: string;
  tenantSlug: string;
  isMember: boolean;
  role: 'admin' | 'member';
}

// ============================================
// Device group types
// ============================================
/**
 * A node of the `device_groups` tree (ex `monitor_groups`, arbitrage A4).
 * The tree carries sites and devices; the transitive closure lives in
 * `group_closure` and drives both RBAC and settings inheritance.
 */
export interface DeviceGroup {
  id: number;
  name: string;
  slug: string;
  description: string | null;
  parentId: number | null;
  sortOrder: number;
  /** The undeletable catch-all group of a tenant. */
  isGeneral: boolean;
  groupNotifications: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface GroupTreeNode extends DeviceGroup {
  children: GroupTreeNode[];
}

export interface CreateGroupRequest {
  name: string;
  description?: string | null;
  parentId?: number | null;
  sortOrder?: number;
  isGeneral?: boolean;
  groupNotifications?: boolean;
}

export interface UpdateGroupRequest {
  name?: string;
  description?: string | null;
  parentId?: number | null;
  sortOrder?: number;
  isGeneral?: boolean;
  groupNotifications?: boolean;
}

export interface MoveGroupRequest {
  newParentId: number | null;
}

// ============================================
// Settings types
// ============================================
/** Inheritance chain: global → group chain → device (arbitrage A4). */
export type SettingsScope = 'global' | 'group' | 'device';

export interface SettingValue {
  value: number;
  source: SettingsScope | 'default';
  sourceId: number | null;
  sourceName: string;
}

export type ResolvedSettings = Record<SettingsKey, SettingValue>;

// ============================================
// Notification types
// ============================================
export interface NotificationChannel {
  id: number;
  name: string;
  type: string;
  config: Record<string, unknown>;
  isEnabled: boolean;
  createdBy: number | null;
  tenantId?: number;
  isShared?: boolean;
  createdAt: string;
  updatedAt: string;
}

export type OverrideMode = 'merge' | 'replace' | 'exclude';

export type NotificationScope = 'global' | 'group' | 'device';

export interface NotificationBinding {
  id: number;
  channelId: number;
  scope: NotificationScope;
  scopeId: number | null;
  overrideMode: OverrideMode;
}

export interface NotificationPluginMeta {
  type: string;
  name: string;
  description: string;
  configFields: NotificationConfigField[];
}

export interface NotificationConfigField {
  key: string;
  label: string;
  type: 'text' | 'password' | 'number' | 'url' | 'textarea' | 'boolean' | 'smtp_server_select';
  placeholder?: string;
  required?: boolean;
}

/**
 * Per-scope opt-in/opt-out of notification categories. `null` means "inherit
 * from the parent scope"; only the global level is fully resolved.
 */
export interface NotificationTypeConfig {
  /** Master switch for the scope. */
  global: boolean | null;
  /** A device became unreachable. */
  down: boolean | null;
  /** A device came back. */
  up: boolean | null;
  /** A configuration drift was detected on a managed device. */
  drift: boolean | null;
  /** A change job failed or rolled back. */
  change: boolean | null;
  /** A monitored threshold (interface saturation, errors, …) was crossed. */
  threshold: boolean | null;
}

export const DEFAULT_NOTIFICATION_TYPES: Required<{
  [K in keyof NotificationTypeConfig]: boolean;
}> = {
  global: true,
  down: true,
  up: true,
  drift: true,
  change: true,
  threshold: true,
};

export interface CreateNotificationChannelRequest {
  name: string;
  type: string;
  config: Record<string, unknown>;
  isEnabled?: boolean;
}

export interface UpdateNotificationChannelRequest {
  name?: string;
  config?: Record<string, unknown>;
  isEnabled?: boolean;
}

// ============================================
// SMTP server types
// ============================================
export interface SmtpServer {
  id: number;
  name: string;
  host: string;
  port: number;
  secure: boolean;
  username: string;
  fromAddress: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateSmtpServerRequest {
  name: string;
  host: string;
  port: number;
  secure: boolean;
  username: string;
  password: string;
  fromAddress: string;
}

export interface UpdateSmtpServerRequest {
  name?: string;
  host?: string;
  port?: number;
  secure?: boolean;
  username?: string;
  /** Omit to keep the stored password. */
  password?: string;
  fromAddress?: string;
}

// ============================================
// App config types
// ============================================
export interface AppConfig {
  allow_2fa: boolean;
  force_2fa: boolean;
  otp_smtp_server_id: number | null;
  obligate_url: string | null;
  obligate_enabled: boolean;
}

/**
 * Obligate SSO gateway settings stored under `obligate_config` in app_config.
 * The raw apiKey is never exposed to clients — only `apiKeySet` (boolean).
 */
export interface ObligateConfig {
  url: string | null;
  apiKeySet: boolean;
  /**
   * Whether the PUBLIC application id is configured. Reported separately from
   * `apiKeySet` because they are two different secrets-classes: `apiKey` is the
   * server-to-server bearer and never leaves the server, `clientId` is the only
   * half allowed in the /authorize URL. `/auth/sso-redirect` fails closed when
   * it is missing, so without this flag an operator sees `apiKeySet: true,
   * enabled: true` and no way to tell why SSO does not work.
   */
  clientIdSet: boolean;
  enabled: boolean;
}

// ============================================
// Team & permission types
// ============================================
export type PermissionLevel = 'ro' | 'rw';
/** Arbitrage A4: `monitor` scope becomes `device`. */
export type PermissionScope = 'group' | 'device';

export interface UserTeam {
  id: number;
  name: string;
  description: string | null;
  canCreate: boolean;
  tenantId: number;
  tenantName?: string;
  createdAt: string;
  updatedAt: string;
}

export interface TeamPermission {
  id: number;
  teamId: number;
  scope: PermissionScope;
  scopeId: number;
  level: PermissionLevel;
}

export interface PermissionSet {
  id: number;
  name: string;
  slug: string;
  /** Values from `CAPABILITIES` in capabilities.ts — the single vocabulary. */
  capabilities: string[];
  isDefault: boolean;
  createdAt: string;
}

export interface UserPermissions {
  canCreate: boolean;
  teams: number[];
  permissions: Record<string, PermissionLevel>;
  /** Feature capabilities the user holds (admin ⇒ all). See capabilities.ts. */
  capabilities: string[];
}

export interface CreateTeamRequest {
  name: string;
  description?: string | null;
  canCreate?: boolean;
}

export interface UpdateTeamRequest {
  name?: string;
  description?: string | null;
  canCreate?: boolean;
}

export interface SetTeamMembersRequest {
  userIds: number[];
}

export interface SetTeamPermissionsRequest {
  permissions: Array<{
    scope: PermissionScope;
    scopeId: number;
    level: PermissionLevel;
  }>;
}

// ============================================
// User API types
// ============================================
export interface CreateUserRequest {
  username: string;
  password: string;
  displayName?: string | null;
  role?: UserRole;
}

export interface UpdateUserRequest {
  username?: string;
  displayName?: string | null;
  role?: UserRole;
  isActive?: boolean;
}

// ============================================
// Import / export types
// ============================================
/**
 * A portable tenant bundle. The entity list grows with each milestone, but
 * the envelope is fixed now: nothing may be exported that cannot be
 * re-imported (arbitrage 1.4 bis — no orphan entity).
 */
export interface ExportBundleMeta {
  /** Bundle format version — bumped on any breaking envelope change. */
  formatVersion: number;
  /** ObliWAN version that produced the bundle. */
  producedBy: string;
  producedAt: string;
  sourceInstance: string | null;
  tenantSlug: string;
  entityCounts: Record<string, number>;
}

export interface ExportBundle {
  meta: ExportBundleMeta;
  /** Entity name → array of exported records, keyed by their stable `uuid`. */
  entities: Record<string, unknown[]>;
}

export type ImportConflictStrategy = 'skip' | 'overwrite' | 'rename' | 'fail';

export interface ImportOptions {
  targetTenantId: number;
  strategy: ImportConflictStrategy;
  /** Validate and report without writing anything. */
  dryRun: boolean;
}

export interface ImportConflict {
  entity: string;
  uuid: string;
  label: string;
  reason: string;
  resolution: ImportConflictStrategy;
}

export interface ImportResult {
  dryRun: boolean;
  created: Record<string, number>;
  updated: Record<string, number>;
  skipped: Record<string, number>;
  conflicts: ImportConflict[];
  errors: string[];
}

// ============================================
// API envelope types
// ============================================
export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  total: number;
  page: number;
  pageSize: number;
}
