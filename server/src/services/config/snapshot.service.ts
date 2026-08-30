// ============================================================================
// ObliWAN — config snapshots: store, deduplicate, read back
// ============================================================================
//
// Implements ARCHITECTURE.md §3.4 and §8.5 / §8.3 of `docs/M4-NCM-contrat.md`.
//
// ┌─ THE DEDUPLICATION IS THE FEATURE ────────────────────────────────────────┐
// │ `UNIQUE(device_id, ncm_hash)`. A router nobody touched bumps              │
// │ `last_seen_at` and `seen_count` and inserts NOTHING. "This configuration  │
// │ has been true since `captured_at` and was last confirmed at              │
// │ `last_seen_at`" is the entire value of the table.                        │
// │                                                                          │
// │ That only works because the hash covers CONFIGURATION and nothing else.  │
// │ `capturedAt`, `device.osVersion`, `coverage[*].recordCount` and          │
// │ `extensions` are stripped by `shared/src/ncm/canonical.ts` before        │
// │ hashing. So:                                                             │
// │   - a firmware upgrade does NOT create a snapshot (it updates            │
// │     `os_version` on the existing row, which is why that column exists);  │
// │   - editing a normalization rule DOES create one, because                │
// │     `normalizationEpoch` is inside the hash on purpose — and the drift    │
// │     run that follows is labelled `renormalization` and is never           │
// │     attributed to a human (§6.5).                                        │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ TENANT SCOPING, RESTATED BECAUSE THE TABLES CANNOT HELP ─────────────────┐
// │ `config_snapshots` and the ten `ncm_*` tables carry NO tenant column.     │
// │ Every read in this file therefore joins `devices` and filters on          │
// │ `devices.tenant_id`. That join is the only thing standing between one    │
// │ customer and another customer's firewall — exactly as the SNMP series    │
// │ tables in M3. A query added here without it is a cross-tenant leak, not   │
// │ a style problem.                                                          │
// └───────────────────────────────────────────────────────────────────────────┘

import { gzipSync, gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import type {
  NcmDocument, NcmResourceKind, NcmDiffReport, NormalizationTrace,
} from '@obliwan/shared';
import {
  NcmDocumentAuthored, NCM_RESOURCE_KINDS, RESOURCE_KIND_TO_COLLECTION,
  ncmHash as computeNcmHash, upgradeNcm, NcmVersionAheadError,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { indexSnapshot, reconcileOrdinals } from './ncmIndex.service';
import { semanticDiff, type SemanticDiffOptions } from '../drift/semanticDiff';

export const SNAPSHOT_SOURCES = [
  'routeros_api', 'ssh', 'rest', 'cwmp', 'pre_change', 'import',
] as const;
export type SnapshotSource = (typeof SNAPSHOT_SOURCES)[number];

// ============================================================================
// Writing
// ============================================================================

export interface StoreSnapshotInput {
  deviceId: number;
  tenantId: number;
  source: SnapshotSource;
  /** The export EXACTLY as the box produced it. Never normalised on disk. */
  raw: string | null;
  doc: NcmDocument;
  osVersion?: string | null;
  model?: string | null;
  normalizationTraces?: NormalizationTrace[];
}

export interface StoreSnapshotResult {
  snapshotId: string;
  /** false when the document was byte-identical to one already stored for this
   *  device: the row was NOT duplicated, only confirmed. */
  created: boolean;
  ncmHash: string;
  source: SnapshotSource;
  previousSnapshotId: string | null;
  seenCount: number;
  /** §3.4's exit metric, measured on this document. */
  ordinalCollisionRate: number;
  /** How many ordinals the reconciliation had to rewrite. Non-zero on an
   *  unchanged device would mean the reconciliation is not idempotent, which
   *  would break the deduplication — worth having in the log. */
  ordinalsRewritten: number;
}

/** sha256 of the raw text BEFORE gzip. gzip is not byte-deterministic across
 *  zlib versions and compression levels, so hashing the compressed bytes would
 *  make an identical export look different after a Node upgrade. */
function rawSha256(raw: string): string {
  return createHash('sha256').update(raw, 'utf8').digest('hex');
}

function countForwardingRelevant(doc: NcmDocument): number {
  return doc.unmodeled.filter((u) => u.forwardingRelevant).length;
}

/** The most recent stored document for a device, upgraded to the current NCM
 *  version. Used as the pairing reference for ordinal reconciliation, and as
 *  the N-1 side of the default comparison. */
export async function latestDocument(deviceId: number): Promise<{
  id: string;
  doc: NcmDocument;
  ncmHash: string;
} | null> {
  const row = await db('config_snapshots')
    .where({ device_id: deviceId })
    .orderBy('captured_at', 'desc')
    .orderBy('id', 'desc')
    .first<{ id: string; ncm: unknown; ncm_hash: string } | undefined>('id', 'ncm', 'ncm_hash');
  if (!row) return null;
  try {
    return { id: String(row.id), doc: upgradeNcm(row.ncm), ncmHash: row.ncm_hash };
  } catch (err) {
    if (err instanceof NcmVersionAheadError) {
      // Written by a newer server (rollback in progress). NEVER diffed, NEVER
      // stripped, and — critically — not used as a pairing reference either:
      // an ordinal paired against a document we cannot read is a guess.
      logger.warn({ deviceId, snapshotId: row.id }, err.message);
      return null;
    }
    throw err;
  }
}

/**
 * Store one collected document.
 *
 * ORDER OF OPERATIONS, AND IT IS NOT NEGOTIABLE:
 *   1. reconcile ordinals against the previous snapshot (§3.4 case 2);
 *   2. re-validate the reconciled document (`NcmDocumentAuthored`);
 *   3. hash;
 *   4. upsert on `(device_id, ncm_hash)`;
 *   5. index, in the SAME transaction, only when a row was actually created.
 *
 * Doing (3) before (1) would store a document whose hash does not describe its
 * own content, because a reconciled `ordinal` changes a derived `semKey` and a
 * `semKey` is inside the hash.
 */
export async function storeSnapshot(input: StoreSnapshotInput): Promise<StoreSnapshotResult> {
  const previous = await latestDocument(input.deviceId);

  const reconciled = reconcileOrdinals(input.doc, previous?.doc ?? null);
  // Strict on WRITE. A parser that invented a field, declared a kind
  // 'unsupported' while emitting records of it, or left a non-complete coverage
  // without a reason fails HERE — in the collector — and not three layers down
  // inside the diff engine.
  const doc = NcmDocumentAuthored.parse(reconciled.doc) as NcmDocument;
  const hash = computeNcmHash(doc);

  const rawGz = input.raw === null ? null : gzipSync(Buffer.from(input.raw, 'utf8'));

  const row = {
    device_id: input.deviceId,
    source: input.source,
    raw_gz: rawGz,
    raw_sha256: input.raw === null ? null : rawSha256(input.raw),
    raw_bytes: input.raw === null ? null : Buffer.byteLength(input.raw, 'utf8'),
    ncm: JSON.stringify(doc),
    ncm_hash: hash,
    ncm_version: doc.ncmVersion,
    sem_key_generation: doc.semKeyGeneration,
    normalization_epoch: doc.normalizationEpoch,
    order_analysis: doc.orderAnalysis,
    os_version: input.osVersion ?? doc.device.osVersion ?? null,
    model: input.model ?? doc.device.model ?? null,
    unmodeled_forwarding_count: countForwardingRelevant(doc),
    captured_at: doc.capturedAt,
    // `config_snapshots_seen_order_chk` enforces `last_seen_at >= captured_at`.
    // `capturedAt` comes from the COLLECTOR's clock and the comparison is made
    // against the DATABASE's, so a host running a few seconds ahead of Postgres
    // would make every insert fail a constraint that exists to catch a dedup
    // bug — not a clock. GREATEST keeps the invariant true without pretending
    // the two clocks agree.
    last_seen_at: db.raw('GREATEST(now(), ?::timestamptz)', [doc.capturedAt]),
  };

  const result = await db.transaction(async (trx) => {
    const inserted = await trx('config_snapshots')
      .insert(row)
      .onConflict(['device_id', 'ncm_hash'])
      .merge({
        // Everything here is OUTSIDE the hash by construction. A firmware
        // upgrade lands on the existing row instead of forking history.
        last_seen_at: db.raw('GREATEST(now(), config_snapshots.captured_at)'),
        seen_count: db.raw('config_snapshots.seen_count + 1'),
        os_version: row.os_version,
        model: row.model,
        updated_at: db.fn.now(),
      })
      .returning<{ id: string; seen_count: number; created: boolean }[]>([
        'id',
        'seen_count',
        // `xmax = 0` is true exactly when this statement INSERTED the row.
        // Comparing seen_count to 1 would misread a row inserted, deleted and
        // re-inserted; the system column cannot be fooled.
        db.raw('(xmax = 0) as created'),
      ]);

    const stored = inserted[0];
    if (stored.created) {
      await indexSnapshot(trx, {
        snapshotId: String(stored.id),
        deviceId: input.deviceId,
        doc,
      });
    }
    return stored;
  });

  if (reconciled.ordinalCollisionRate > 0.02) {
    // §3.4 makes this a milestone exit criterion, not a curiosity: above ~2 %
    // the key design itself has to be revisited.
    logger.warn(
      {
        deviceId: input.deviceId,
        ordinalCollisionRate: reconciled.ordinalCollisionRate,
        ruleCount: reconciled.ruleCount,
      },
      'ordinalCollisionRate above the 2% threshold of the NCM study §3.4',
    );
  }

  if (input.normalizationTraces && input.normalizationTraces.length > 0) {
    logger.debug(
      { deviceId: input.deviceId, traces: input.normalizationTraces.length },
      'Normalization traces produced',
    );
  }

  return {
    snapshotId: String(result.id),
    created: result.created,
    ncmHash: hash,
    source: input.source,
    previousSnapshotId: previous?.id ?? null,
    seenCount: Number(result.seen_count),
    ordinalCollisionRate: reconciled.ordinalCollisionRate,
    ordinalsRewritten: reconciled.rewritten,
  };
}

// ============================================================================
// Reading — every query joins `devices` and filters on tenant_id
// ============================================================================

export interface SnapshotSummary {
  id: string;
  uuid: string;
  deviceId: number;
  deviceName: string;
  source: string;
  ncmHash: string;
  ncmVersion: number;
  semKeyGeneration: number;
  normalizationEpoch: string;
  orderAnalysis: string;
  osVersion: string | null;
  model: string | null;
  unmodeledForwardingCount: number;
  rawBytes: number | null;
  hasRaw: boolean;
  capturedAt: string;
  lastSeenAt: string;
  seenCount: number;
}

const SUMMARY_COLUMNS = [
  'cs.id', 'cs.uuid', 'cs.device_id', 'cs.source', 'cs.ncm_hash', 'cs.ncm_version',
  'cs.sem_key_generation', 'cs.normalization_epoch', 'cs.order_analysis',
  'cs.os_version', 'cs.model', 'cs.unmodeled_forwarding_count', 'cs.raw_bytes',
  'cs.captured_at', 'cs.last_seen_at', 'cs.seen_count', 'd.name as device_name',
];

interface SummaryRow {
  id: string;
  uuid: string;
  device_id: number;
  source: string;
  ncm_hash: string;
  ncm_version: number;
  sem_key_generation: number;
  normalization_epoch: string;
  order_analysis: string;
  os_version: string | null;
  model: string | null;
  unmodeled_forwarding_count: number;
  raw_bytes: number | null;
  captured_at: Date;
  last_seen_at: Date;
  seen_count: number;
  device_name: string;
}

function toSummary(r: SummaryRow): SnapshotSummary {
  return {
    id: String(r.id),
    uuid: r.uuid,
    deviceId: r.device_id,
    deviceName: r.device_name,
    source: r.source,
    ncmHash: r.ncm_hash,
    ncmVersion: r.ncm_version,
    semKeyGeneration: r.sem_key_generation,
    normalizationEpoch: r.normalization_epoch,
    orderAnalysis: r.order_analysis,
    osVersion: r.os_version,
    model: r.model,
    unmodeledForwardingCount: r.unmodeled_forwarding_count,
    rawBytes: r.raw_bytes === null ? null : Number(r.raw_bytes),
    hasRaw: r.raw_bytes !== null,
    capturedAt: new Date(r.captured_at).toISOString(),
    lastSeenAt: new Date(r.last_seen_at).toISOString(),
    seenCount: Number(r.seen_count),
  };
}

/** The tenant-scoped base query. EVERY read in this file starts here. */
function scoped(tenantId: number) {
  return db('config_snapshots as cs')
    .join('devices as d', 'd.id', 'cs.device_id')
    .where('d.tenant_id', tenantId);
}

/**
 * Snapshots of one device, or of the whole tenant when `deviceId` is omitted.
 *
 * Tenant scoping goes through `devices` (see `scoped()`): `config_snapshots`
 * carries no tenant column of its own, so that join is the only thing between
 * one customer and another customer's configurations.
 */
export async function listSnapshots(
  tenantId: number,
  deviceId: number | undefined,
  opts: { limit?: number; offset?: number } = {},
): Promise<SnapshotSummary[]> {
  const base = scoped(tenantId);
  if (deviceId !== undefined) void base.andWhere('cs.device_id', deviceId);
  const rows = await base
    .orderBy('cs.captured_at', 'desc')
    .orderBy('cs.id', 'desc')
    .limit(Math.min(opts.limit ?? 50, 200))
    .offset(opts.offset ?? 0)
    .select<SummaryRow[]>(SUMMARY_COLUMNS);
  return rows.map(toSummary);
}

export async function getSnapshot(
  tenantId: number,
  snapshotId: string,
): Promise<SnapshotSummary | null> {
  const row = await scoped(tenantId)
    .andWhere('cs.id', snapshotId)
    .first<SummaryRow | undefined>(SUMMARY_COLUMNS);
  return row ? toSummary(row) : null;
}

/** The document itself, upgraded to the current NCM version on read (§8.2: we
 *  never rewrite stored rows; the version bump happens here). */
export async function getSnapshotDocument(
  tenantId: number,
  snapshotId: string,
): Promise<{ summary: SnapshotSummary; doc: NcmDocument } | null> {
  const row = await scoped(tenantId)
    .andWhere('cs.id', snapshotId)
    .first<(SummaryRow & { ncm: unknown }) | undefined>([...SUMMARY_COLUMNS, 'cs.ncm']);
  if (!row) return null;
  return { summary: toSummary(row), doc: upgradeNcm(row.ncm) };
}

/**
 * The archive of reference, decompressed.
 *
 * It is the REDACTED export (`show-sensitive=no`, hard-wired in
 * `collect.service.ts`) — which is why serving it needs `CONFIG_READ` and not
 * `SECRET_READ`. It is also the escape hatch of §8.3: a future parser can
 * re-derive a richer document from it without going back to 300 routers.
 */
export async function getSnapshotRaw(
  tenantId: number,
  snapshotId: string,
): Promise<{ text: string; sha256: string | null; capturedAt: string; deviceName: string } | null> {
  const row = await scoped(tenantId)
    .andWhere('cs.id', snapshotId)
    .first<
      { raw_gz: Buffer | null; raw_sha256: string | null; captured_at: Date; device_name: string } | undefined
    >('cs.raw_gz', 'cs.raw_sha256', 'cs.captured_at', 'd.name as device_name');
  if (!row) return null;
  if (!row.raw_gz) return null;
  return {
    text: gunzipSync(row.raw_gz).toString('utf8'),
    sha256: row.raw_sha256,
    capturedAt: new Date(row.captured_at).toISOString(),
    deviceName: row.device_name,
  };
}

// ============================================================================
// The NCM tree — what the UI renders
// ============================================================================

export interface NcmTreeNode {
  kind: NcmResourceKind;
  label: string;
  coverage: NcmDocument['coverage'][NcmResourceKind];
  /** `orderGroup -> resources`, so a firewall renders chain by chain rather
   *  than as one 200-line list whose positions mean nothing across chains. */
  groups: Array<{ group: string | null; resources: unknown[] }>;
  count: number;
}

export interface NcmTree {
  snapshot: SnapshotSummary;
  device: NcmDocument['device'];
  orderAnalysis: string;
  unmodeled: NcmDocument['unmodeled'];
  nodes: NcmTreeNode[];
}

const KIND_LABEL: Readonly<Record<NcmResourceKind, string>> = {
  interface: 'Interfaces',
  dhcpClient: 'DHCP clients',
  vlan: 'VLANs',
  route: 'Static routes',
  firewallRule: 'Firewall rules',
  natRule: 'NAT rules',
  dhcpScope: 'DHCP scopes',
  ipsecPeer: 'IPsec peers',
  localUser: 'Local users',
  service: 'Management services',
  qosRule: 'QoS rules',
};

export async function getNcmTree(tenantId: number, snapshotId: string): Promise<NcmTree | null> {
  const loaded = await getSnapshotDocument(tenantId, snapshotId);
  if (!loaded) return null;
  const { doc, summary } = loaded;

  const nodes: NcmTreeNode[] = NCM_RESOURCE_KINDS.map((kind) => {
    const key = RESOURCE_KIND_TO_COLLECTION[kind] as keyof NcmDocument['resources'];
    const list = (doc.resources[key] ?? []) as unknown as Array<Record<string, unknown>>;
    const groups = new Map<string | null, unknown[]>();
    for (const r of list) {
      const group =
        kind === 'firewallRule' || kind === 'natRule'
          ? (r.chainName ? `${String(r.chain)}:${String(r.chainName)}` : String(r.chain))
          : kind === 'qosRule'
            ? String(r.queueClass)
            : null;
      const bucket = groups.get(group);
      if (bucket) bucket.push(r);
      else groups.set(group, [r]);
    }
    return {
      kind,
      label: KIND_LABEL[kind],
      coverage: doc.coverage[kind],
      groups: [...groups.entries()].map(([group, resources]) => ({ group, resources })),
      count: list.length,
    };
  });

  return {
    snapshot: summary,
    device: doc.device,
    orderAnalysis: doc.orderAnalysis,
    unmodeled: doc.unmodeled,
    nodes,
  };
}

// ============================================================================
// Comparison
// ============================================================================

export interface SnapshotComparison {
  from: SnapshotSummary;
  to: SnapshotSummary;
  /** Why the two documents differ at all, as far as the metadata can tell.
   *  `renormalization` and `model_upgrade` are OUR OWN doing and must never be
   *  attributed to a human (§6.5) — surfaced here so the UI can say so. */
  cause: 'renormalization' | 'model_upgrade' | 'config';
  report: NcmDiffReport;
}

/**
 * Compare two snapshots of ONE device, oriented `from` (the older / desired
 * side) -> `to` (the newer / observed side).
 *
 * With no ids this is the N/N-1 comparison: "what changed since the last time
 * we looked". Both sides go through `upgradeNcm` first, because §8.2 forbids
 * diffing two documents of different `ncmVersion` directly.
 */
export async function compareSnapshots(
  tenantId: number,
  deviceId: number,
  opts: { fromId?: string; toId?: string } & Partial<SemanticDiffOptions> = {},
): Promise<SnapshotComparison | null> {
  let toId = opts.toId;
  let fromId = opts.fromId;

  if (!toId || !fromId) {
    const recent = await scoped(tenantId)
      .andWhere('cs.device_id', deviceId)
      .orderBy('cs.captured_at', 'desc')
      .orderBy('cs.id', 'desc')
      .limit(2)
      .select<{ id: string }[]>('cs.id');
    if (recent.length < 2) return null;
    toId = toId ?? String(recent[0].id);
    fromId = fromId ?? String(recent[1].id);
  }

  const [from, to] = await Promise.all([
    getSnapshotDocument(tenantId, fromId),
    getSnapshotDocument(tenantId, toId),
  ]);
  if (!from || !to) return null;
  if (from.summary.deviceId !== deviceId || to.summary.deviceId !== deviceId) return null;

  const report = semanticDiff(from.doc, to.doc, {
    scope: opts.scope ?? 'managed_only',
    claimedKinds: opts.claimedKinds,
    fuzzy: opts.fuzzy,
  });

  const cause =
    from.doc.ncmVersion !== to.doc.ncmVersion
      ? 'model_upgrade'
      : from.doc.normalizationEpoch !== to.doc.normalizationEpoch
        ? 'renormalization'
        : 'config';

  return { from: from.summary, to: to.summary, cause, report };
}

/** Deletion is a retention concern and not exposed over HTTP in M4; this exists
 *  so the retention job has one door and cannot forget the tenant filter. */
export async function deleteSnapshot(tenantId: number, snapshotId: string): Promise<boolean> {
  const owned = await scoped(tenantId).andWhere('cs.id', snapshotId).first<{ id: string } | undefined>('cs.id');
  if (!owned) return false;
  await db('config_snapshots').where({ id: snapshotId }).del();
  return true;
}

/**
 * The name of a live SECOND UPLINK on this device, or null.
 *
 * ┌─ WHY IT LIVES HERE AND NOT IN THE CHANGE PATH ───────────────────────────┐
 * │ Two callers need this answer and they MUST agree: `resolveSafetyNet` in   │
 * │ `apply.service` shows the level BEFORE launch, and its counterpart in     │
 * │ `safeApply` reports the level the operator finally lives with — §8.3 says │
 * │ the job stops when the second is worse than the first. Two copies of this │
 * │ predicate drifting apart would halt every DrayTek write with no readable  │
 * │ reason, so there is one, and it sits with the snapshot it reads.          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Reads the latest NCM rather than a column: `interface.type === 'lte'` is a
 * modelled fact with a parser behind it, whereas a column would be a second
 * place for the same truth to rot. A device with no snapshot answers null —
 * absence of evidence — and the caller then files it `degraded`, the closed
 * direction.
 *
 * It does NOT prove the SIM has credit or the operator has coverage. Nothing
 * short of a call does, and the wording at both call sites says so instead of
 * implying a guarantee.
 */
export async function findSecondUplink(deviceId: number): Promise<string | null> {
  const row = await latestDocument(deviceId).catch(() => null);
  if (!row) return null;
  const uplink = row.doc.resources.interfaces.find((i) => i.type === 'lte' && !i.disabled);
  return uplink ? uplink.name : null;
}
