// ObliWAN client — NCM / drift DTOs (M4).
//
// Same rule as `types/fleet.ts` and `types/telemetry.ts`: these are the shapes
// the CLIENT expects on the wire. The VOCABULARIES are imported from
// `@obliwan/shared` and never redeclared here — `NcmDocument`,
// `NcmDiffFinding`, `DiffSeverity`, `CoverageState`, `MatchMethod` and the
// resource kinds are the frozen M4 contract and this file must not fork them.
// What lives here is only the ENVELOPE the HTTP routes wrap them in (the
// `config_snapshots`, `drift_runs` and `drift_findings` rows of migration 007),
// until the lead consolidates it into `shared/`.
//
// ── SECTION 8.2 IS LOAD-BEARING IN EVERY SHAPE BELOW ────────────────────────
// No secret crosses this boundary. `raw` is the REDACTED export
// (`/export show-sensitive=no`, hard-wired server-side per R10), a password is
// a `SecretFingerprint` and never a value, and `intentValue` / `actualValue`
// carry redacted material only. The client additionally runs `utils/secretScan`
// over everything it is about to paint, because "the server guarantees it" is a
// claim the UI is in a position to check and therefore should.

import type {
  CoverageState,
  DiffKind,
  DiffScope,
  DiffSeverity,
  MatchMethod,
  NcmDocumentStored,
  NcmFieldDiff,
  NcmResourceKind,
  OrderAnalysisState,
  SuppressionReason,
} from '@obliwan/shared';

// ── Snapshots ───────────────────────────────────────────────────────────────

/** `config_snapshots.source` (migration 007). */
export type SnapshotSource =
  | 'routeros_api' | 'ssh' | 'rest' | 'cwmp' | 'pre_change' | 'import';

/**
 * One row of `config_snapshots`, without the document.
 *
 * `seenCount`/`lastSeenAt` are not decoration: the `UNIQUE(device_id, ncm_hash)`
 * deduplication means a router nobody touched inserts NOTHING and bumps these
 * two instead. "This configuration has been true since `capturedAt` and was
 * last confirmed at `lastSeenAt`" is the whole value of that constraint, and
 * the UI has to say it or the snapshot list reads as a broken collector.
 */
export interface ConfigSnapshotSummary {
  id: number;
  uuid: string;
  deviceId: number;
  /** Present when the list endpoint joins `devices`. */
  deviceName?: string | null;
  siteId?: number | null;
  siteName?: string | null;
  source: SnapshotSource;
  ncmHash: string;
  ncmVersion: number;
  semKeyGeneration: number;
  normalizationEpoch: string;
  orderAnalysis: OrderAnalysisState;
  /** Deliberately OUTSIDE `ncmHash` (§8.5): a firmware upgrade must be visible
   *  without manufacturing a snapshot or a finding. */
  osVersion: string | null;
  model: string | null;
  /** Count of `unmodeled[]` sections that can influence forwarding. */
  unmodeledForwardingCount: number;
  rawBytes: number | null;
  rawSha256: string | null;
  capturedAt: string;
  lastSeenAt: string;
  seenCount: number;
}

/** A snapshot with its document. `ncm` is read with `NcmDocumentStored`
 *  semantics — unknown keys from a NEWER server are preserved, never stripped. */
export interface ConfigSnapshotDetail extends ConfigSnapshotSummary {
  ncm: NcmDocumentStored | null;
}

/** The redacted `/export` text behind `raw_gz`, decompressed server-side. */
export interface SnapshotRawText {
  snapshotId: number;
  text: string;
  sha256: string | null;
  /** The server states it applied the redaction. The client still scans. */
  redacted: boolean;
}

// ── Drift ───────────────────────────────────────────────────────────────────

/** `drift_runs.status`. `error` != `unreachable`, and the distinction is
 *  load-bearing: a box we could not reach is an infrastructure event, a run
 *  that blew up is our own bug. The UI must never collapse them. */
export type DriftStatus = 'in_sync' | 'drifted' | 'error' | 'unreachable';

/** `drift_runs.cause`. `renormalization` and `model_upgrade` are OURS: §6.5
 *  excludes them from attribution by construction, and the UI labels them so
 *  nobody hunts for the human who "changed" 200 devices at 03:00. */
export type DriftCause =
  | 'scheduled' | 'manual' | 'post_change'
  | 'renormalization' | 'model_upgrade' | 'takeover';

export interface DriftSuppression {
  resource: NcmResourceKind;
  reason: SuppressionReason;
}

export interface DriftRunSummary {
  id: number;
  uuid: string;
  deviceId: number;
  deviceName?: string | null;
  siteId?: number | null;
  siteName?: string | null;
  renderId: number | null;
  snapshotId: number | null;
  status: DriftStatus;
  errorReason: string | null;
  cause: DriftCause;
  scope: DiffScope;
  findingsCount: number;
  ignoredCount: number;
  /** Reorderings with no effect on forwarding. ONE aggregated line in the UI,
   *  never N findings (§4.4). This counter is the instrumentation of that
   *  anti-noise lever and the reason the R3 budget can be measured per lever. */
  inertMoveCount: number;
  /** Objects observed outside any claimed template section under
   *  `managed_only`. Rendered as a permanent, visible blind-spot counter — the
   *  Q2 compromise must not become a silent one. */
  outOfScopeCount: number;
  maxSeverity: DiffSeverity | null;
  ncmVersion: number;
  normalizationEpoch: string | null;
  orderAnalysis: OrderAnalysisState;
  suppressed: DriftSuppression[];
  startedAt: string;
  finishedAt: string | null;
}

/** One row of `drift_findings`. ONE row per RESOURCE carrying N `fieldDiffs` —
 *  never one row per field. */
export interface DriftFinding {
  id: number;
  runId: number;
  path: string;
  semKey: string;
  resource: NcmResourceKind;
  kind: DiffKind;
  severity: DiffSeverity;
  matchMethod: MatchMethod;
  matchConfidence: number;
  predicateChanged: boolean;
  fieldDiffs: NcmFieldDiff[];
  /** `moved` only: the DECISIVE rules this one crossed. An empty array here is
   *  a database-level violation (migration 007) precisely because an inert move
   *  must never reach this list. */
  crossed: string[];
  intentValue: unknown;
  actualValue: unknown;
  /** The readable COMPLEMENT to the semantic diff (§4.2). Never the truth. */
  textPatch: string | null;
  ignored: boolean;
  ignoredByRule: number | null;
  legacySemKey: string | null;
}

export interface DriftRunDetail extends DriftRunSummary {
  findings: DriftFinding[];
}

// ── The view model both diff sources render through ─────────────────────────

/**
 * ONE shape for the semantic diff panel, whatever produced it.
 *
 * `ConfigDiff` renders this and nothing else, so the same component draws:
 *   - a drift run's `DriftFinding[]` (server engine, intent -> observed), and
 *   - a snapshot N/N-1 comparison computed in the browser from two NCM
 *     documents (`utils/ncmCompare`), which has no intent side at all.
 *
 * The two differ in what they are ENTITLED to claim, and the difference is
 * carried explicitly rather than hidden: a browser-side comparison has no
 * normalization rules, no ignore rules and no severity model, so it reports
 * `severity: 'info'` and `origin: 'local'`, and the UI says so above the list.
 */
export interface SemanticChange {
  /** Stable within one list. `drift_findings.id` server-side, the finding path
   *  locally — never an array index, which would change under every insert. */
  id: string;
  kind: DiffKind;
  resource: NcmResourceKind;
  semKey: string;
  path: string;
  severity: DiffSeverity;
  matchMethod: MatchMethod;
  matchConfidence: number;
  predicateChanged: boolean;
  fieldDiffs: NcmFieldDiff[];
  crossed: string[];
  beforeValue: unknown;
  afterValue: unknown;
  textPatch: string | null;
  ignored: boolean;
  ignoredByRule: number | null;
  origin: 'server' | 'local';
  /** Server findings only — the row id needed to persist an ignore. */
  findingId?: number;
}

/** What `ConfigDiff` needs beyond the list itself to be honest about it. */
export interface SemanticChangeSet {
  changes: SemanticChange[];
  /** Aggregated into ONE line. Never expanded into findings. */
  inertMoveCount: number;
  outOfScopeCount: number;
  suppressed: DriftSuppression[];
  scope: DiffScope;
  orderAnalysis: OrderAnalysisState;
  origin: 'server' | 'local';
}

// ── Coverage, for the tree ──────────────────────────────────────────────────

export interface CoverageView {
  kind: NcmResourceKind;
  state: CoverageState;
  reason: string | null;
  via: string | null;
  recordCount: number;
}
