// ============================================================================
// @obliwan/shared — Socket.io event names
// ============================================================================
//
// Namespaces:
//   wan:*           fleet / config / change domain events (ObliWAN specific)
//   group:*         device group tree mutations
//   settings:*      hierarchical settings mutations
//   notification:*  channel dispatch + DB-backed live alerts
//
// Only `INITIAL_DATA`, `group:*`, `settings:*` and `notification:*` are wired
// in M1 — everything under `wan:*` is declared here so the vocabulary exists
// once. Declaring a name costs nothing; renaming one after the client ships
// costs a release.
//
// Rooms (server-side convention, see `socket.ts`):
//   tenant:{tenantId}                 every event scoped to a tenant
//   tenant:{tenantId}:notifications   live alerts only
//   device:{deviceId}                 per-device subscription
//   job:{jobId} / rollout:{rolloutId} live progress of one run

// ── Server → Client ─────────────────────────────────────────────────────────
export const SOCKET_EVENTS = {
  /** Snapshot pushed right after the socket authenticates. */
  INITIAL_DATA: 'initialData',

  // ── Fleet & presence (M2 — decisions D4/D5) ──────────────────────────
  /** Aggregated presence of a site (how many devices are up over PPP). */
  SITE_PRESENCE: 'wan:site:presence',
  SITE_CREATED: 'wan:site:created',
  SITE_UPDATED: 'wan:site:updated',
  SITE_DELETED: 'wan:site:deleted',
  DEVICE_CREATED: 'wan:device:created',
  DEVICE_UPDATED: 'wan:device:updated',
  DEVICE_DELETED: 'wan:device:deleted',
  /** PPP session came up / went down on the concentrator. */
  DEVICE_PRESENCE: 'wan:device:presence',
  /** K7 verdict changed (TUNNEL_DOWN_SITE_UP, SITE_DOWN, WAN_FAILOVER, …). */
  DEVICE_REACHABILITY: 'wan:device:reachability',
  /** Transport circuit breaker opened / closed for a device channel. */
  DEVICE_TRANSPORT_STATE: 'wan:device:transportState',
  /** An unknown PPP username showed up on the concentrator (quarantine). */
  DISCOVERY_NEW: 'wan:discovery:new',
  DISCOVERY_RESOLVED: 'wan:discovery:resolved',

  // ── Telemetry (M3) ───────────────────────────────────────────────────
  INTERFACE_SAMPLE: 'wan:telemetry:sample',
  THRESHOLD_TRIGGERED: 'wan:telemetry:threshold',

  // ── Configuration & drift (M4 / M8) ──────────────────────────────────
  SNAPSHOT_CREATED: 'wan:config:snapshot',
  DRIFT_RUN_STARTED: 'wan:drift:runStarted',
  DRIFT_RUN_FINISHED: 'wan:drift:runFinished',
  DRIFT_FINDING: 'wan:drift:finding',
  /** K6: a finding was attributed to an identity (or marked unattributed). */
  DRIFT_ATTRIBUTED: 'wan:drift:attributed',

  // ── Templates & plan (M5) ────────────────────────────────────────────
  TEMPLATE_PUBLISHED: 'wan:template:published',
  PLAN_READY: 'wan:plan:ready',
  /** The device moved under us: `base_state_hash` no longer matches. */
  PLAN_INVALIDATED: 'wan:plan:invalidated',

  // ── Change jobs (M6 — decision D3, killers K1/K2) ────────────────────
  //
  // The five names below were declared at M2. Reviewed at M6 against the
  // question "can an operator watch a real apply with only these?", the answer
  // was no on three counts, and the three additions are all about the NET:
  //
  //  - between `started` and `finished` an operator cannot tell whether a net
  //    exists on the box. `JOB_ARMED` is the instant the dead-man is installed
  //    — the single most important moment of the whole job (§8.3), and the one
  //    that decides whether closing the laptop is safe;
  //  - `JOB_SOAKING` says the change is LIVE and being watched, with a
  //    deadline. Without it, five silent minutes of soak read as a hung job and
  //    somebody starts clicking;
  //  - `JOB_DISARMED` is the counterpart of `JOB_ARMED`: until it fires, the
  //    router still carries a scheduler that will revert the change at its next
  //    boot. "Succeeded" without a visible disarm is a lie waiting for a power
  //    cut.
  //
  // `JOB_STEP` carries every step including these three; the dedicated events
  // exist because a UI must not have to pattern-match on a step kind to render
  // the one state transition that matters for safety.
  JOB_QUEUED: 'wan:job:queued',
  JOB_STARTED: 'wan:job:started',
  JOB_STEP: 'wan:job:step',
  /** The dead-man is now installed ON the device (or on its peer). Carries the
   *  `SafetyLevel` actually obtained, which may be worse than the one planned. */
  JOB_ARMED: 'wan:job:armed',
  /** Applied and verified; watching for `soakUntil`. The dead-man is still on. */
  JOB_SOAKING: 'wan:job:soaking',
  /** The dead-man has been removed and confirmed gone. */
  JOB_DISARMED: 'wan:job:disarmed',
  JOB_FINISHED: 'wan:job:finished',
  /** The dead-man fired and the device restored itself. */
  JOB_ROLLED_BACK: 'wan:job:rolledBack',
  /** Write kill-switch flipped — global or per tenant. Every client drops its
   *  apply buttons on this one, whatever page it is on. */
  KILL_SWITCH_CHANGED: 'wan:killSwitch:changed',

  // ── Rollouts (M7 — killer K3) ────────────────────────────────────────
  ROLLOUT_PROGRESS: 'wan:rollout:progress',
  ROLLOUT_WAVE_CHANGED: 'wan:rollout:wave',
  ROLLOUT_FINISHED: 'wan:rollout:finished',

  // ── ACS TR-069 (M10) ─────────────────────────────────────────────────
  ACS_INFORM: 'wan:acs:inform',
  ACS_TASK_UPDATED: 'wan:acs:task',

  // ── Groups ───────────────────────────────────────────────────────────
  GROUP_CREATED: 'group:created',
  GROUP_UPDATED: 'group:updated',
  GROUP_DELETED: 'group:deleted',
  GROUP_MOVED: 'group:moved',

  // ── Settings ─────────────────────────────────────────────────────────
  SETTINGS_UPDATED: 'settings:updated',

  // ── Notifications ────────────────────────────────────────────────────
  /** A channel dispatch happened (used by the notification log view). */
  NOTIFICATION_SENT: 'notification:sent',
  /** New DB-backed live alert, emitted to tenant:{tenantId}:notifications. */
  NOTIFICATION_NEW: 'notification:new',
} as const;

export type SocketEvent = (typeof SOCKET_EVENTS)[keyof typeof SOCKET_EVENTS];

// ── Client → Server ─────────────────────────────────────────────────────────
export const CLIENT_EVENTS = {
  DEVICE_SUBSCRIBE: 'wan:device:subscribe',
  DEVICE_UNSUBSCRIBE: 'wan:device:unsubscribe',
  JOB_SUBSCRIBE: 'wan:job:subscribe',
  JOB_UNSUBSCRIBE: 'wan:job:unsubscribe',
  ROLLOUT_SUBSCRIBE: 'wan:rollout:subscribe',
  ROLLOUT_UNSUBSCRIBE: 'wan:rollout:unsubscribe',
} as const;

export type ClientEvent = (typeof CLIENT_EVENTS)[keyof typeof CLIENT_EVENTS];

// ── Room name helpers ───────────────────────────────────────────────────────
// Kept here so server and client cannot drift apart on a string template.

export const socketRooms = {
  tenant: (tenantId: number): string => `tenant:${tenantId}`,
  tenantNotifications: (tenantId: number): string => `tenant:${tenantId}:notifications`,
  device: (deviceId: number): string => `device:${deviceId}`,
  job: (jobId: number): string => `job:${jobId}`,
  rollout: (rolloutId: number): string => `rollout:${rolloutId}`,
} as const;
