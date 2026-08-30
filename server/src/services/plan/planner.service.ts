// ============================================================================
// ObliWAN — planner.service : diff(ncm_desired, ncm_observed) -> PlanOp[]
// ============================================================================
//
// M5 COMPILES PLANS. IT APPLIES NOTHING. There is no code path in this file, or
// reachable from it, that opens a socket to an equipment. Applying is M6.
//
// ┌─ THE THREE GUARANTEES THIS FILE OWES THE REST OF THE PRODUCT ────────────┐
// │                                                                          │
// │ 1. N3 — NO DELETION WITHOUT A COMPLETE COLLECTION.                       │
// │    `semanticDiff` gates `extra` on the DESIRED side being complete; it   │
// │    does NOT gate it on the OBSERVED side, because a diff report is a     │
// │    statement about two documents and an `extra` really is extra.         │
// │    A PLAN is different: it is an instruction to destroy something on a    │
// │    customer's router. So a `delete` op is emitted only when              │
// │    `observed.coverage[kind].state === 'complete'`. Anything else becomes │
// │    a `blocked` op naming the record that was NOT deleted and why.        │
// │    Without this, one truncated `/export` — a session timeout, a paged    │
// │    read cut short, a `/export` that hit its own line limit — compiles    │
// │    into a plan that empties a site's firewall. This is the single most   │
// │    important property of this file.                                      │
// │                                                                          │
// │ 2. `baseStateHash` — A PLAN IS A STATEMENT ABOUT ONE STATE OF THE WORLD. │
// │    The plan records the `ncm_hash` of the snapshot it was computed        │
// │    against. `assertPlanFresh()` refuses it the moment the device's       │
// │    current snapshot hashes differently. Somebody opened Winbox between   │
// │    compilation and approval? The plan is dead, and recompiling is the    │
// │    only way forward. A stale plan applied to a box somebody edited is    │
// │    how an operator deletes a rule they never saw.                        │
// │                                                                          │
// │ 3. ORDER — CREATE BEFORE REFERENCING, DELETE AFTER DEREFERENCING.        │
// │    Ops carry `dependsOn` and are emitted in an order that satisfies it.  │
// └──────────────────────────────────────────────────────────────────────────┘
//
// ┌─ WHAT THIS FILE DOES NOT DECIDE ─────────────────────────────────────────┐
// │ `mgmtPathVerdict` is ALWAYS `'indeterminate'` at M5. §6.4 says a verdict │
// │ of `accept` requires proving the management path survives, which needs   │
// │ the forwarding engine of K2 — milestone M6. `indeterminate` is the       │
// │ fail-closed value and this file is not allowed to invent the other one.  │
// │ `riskScoring.ts` marks the ops K2 will have to look at (`tunnelCritical`)│
// │ and stops there.                                                         │
// └──────────────────────────────────────────────────────────────────────────┘

import crypto from 'crypto';
import type { Knex } from 'knex';
import type {
  ApplyPlan, BlastRadius, NcmDiffFinding, NcmDiffReport, NcmDocument,
  NcmOrderedRule, NcmResource, NcmResourceKind, PlanOp, PlanOpKind, PlanSource,
  RiskLevel, Selector,
} from '@obliwan/shared';
import {
  NCM_RESOURCE_KINDS, ORDERED_RESOURCE_KINDS, RESOURCE_KIND_TO_COLLECTION,
  coverageOf, ncmHash, planRisk, upgradeNcm,
} from '@obliwan/shared';
import { db } from '../../db';
import { topoSort, findCycles, CycleError } from '../../utils/topoSort';
import { semanticDiff } from '../drift/semanticDiff';
import { latestDocument } from '../config/snapshot.service';
import {
  renderRevisionForDevice, loadDevice,
  type RenderOptions, type RenderResultRecord, type DeviceRow,
} from '../template/render.service';
import {
  buildMgmtPathFacts, scoreOp, classifyResource,
  type MgmtPathFacts, type RiskAssessment,
} from './riskScoring';

// ============================================================================
// Constants
// ============================================================================

/**
 * How long a compiled plan may sit before it must be recompiled.
 *
 * A plan is perishable for the same reason `baseStateHash` exists: it describes
 * a world. Thirty minutes is long enough for a four-eyes approval and short
 * enough that "the plan I approved" and "the box as it is" have not had time to
 * become two different things through anything other than an edit — which
 * `baseStateHash` catches anyway. The expiry is the belt; the hash is the
 * braces, and it is the braces that carry the load.
 */
export const PLAN_TTL_MS = 30 * 60 * 1000;

/** Every plan compiled by M5 comes from a template. `intent` (K4), `refactor`
 *  and `restore` arrive later and reuse the same compiler. */
const DEFAULT_SOURCE: PlanSource = 'template';

// ============================================================================
// Errors
// ============================================================================

export class PlanCompilationError extends Error {
  constructor(message: string, readonly reason: string) {
    super(message);
    this.name = 'PlanCompilationError';
  }
}

/**
 * The refusal of guarantee 2. Carries both hashes so the operator sees that the
 * world moved, and the client can offer "recompile" rather than "retry".
 */
export class StalePlanError extends Error {
  constructor(
    readonly deviceId: number,
    readonly expected: string,
    readonly actual: string | null,
  ) {
    super(
      actual === null
        ? `The plan for device #${deviceId} was computed against a snapshot that no longer ` +
          'exists. Recompile it.'
        : `The plan for device #${deviceId} is STALE: it was computed against the device state ` +
          `${expected.slice(0, 12)}… and the device is now at ${actual.slice(0, 12)}…. ` +
          'Somebody changed the configuration since the plan was compiled — recompile it ' +
          'and review the new operations before approving.',
    );
    this.name = 'StalePlanError';
  }
}

export class PlanExpiredError extends Error {
  constructor(readonly deviceId: number, readonly expiresAt: string) {
    super(
      `The plan for device #${deviceId} expired at ${expiresAt}. A plan is a statement about ` +
        'one state of the world; past its expiry it must be recompiled, not approved.',
    );
    this.name = 'PlanExpiredError';
  }
}

// ============================================================================
// Result types
// ============================================================================

export interface PlanCompilation {
  plan: ApplyPlan;
  /** Enriched, non-persisted view for the PlanPage: signals per op and the
   *  reasons behind every suppression. Never fed back into `assertPlanFresh` —
   *  the plan itself is the contract. */
  detail: {
    deviceName: string;
    renderId: string | null;
    revisionId: string;
    revision: number;
    templateId: string | null;
    observedSnapshotId: string;
    observedCapturedAt: string;
    /** Resource kinds the template claims. Everything else was not compared. */
    claimedKinds: NcmResourceKind[];
    diff: NcmDiffReport;
    /** Per-op risk signals, indexed by `seq`. */
    signals: Record<number, RiskAssessment>;
    /** Kinds where a deletion was refused by N3, with the observed coverage. */
    deletionsBlocked: { resource: NcmResourceKind; coverage: string; count: number }[];
    warnings: string[];
  };
}

export interface CompileOptions {
  /** Reuse an explicit revision instead of the assignment resolution. */
  revisionId?: string | number | null;
  /** Persist the `config_renders` row. Default TRUE — a plan whose desired
   *  state has no row is a plan with no provenance. */
  persistRender?: boolean;
  /** Compare against a specific snapshot instead of the latest. */
  snapshotId?: string | null;
  source?: PlanSource;
  createdBy?: number | null;
  trx?: Knex | Knex.Transaction;
}

// ============================================================================
// Compilation
// ============================================================================

/**
 * Compile a plan for ONE device.
 *
 * Reads: the device (tenant-scoped), the applicable template revision, the
 * variables, the latest snapshot. Writes: at most one `config_renders` row.
 * Touches no equipment.
 */
export async function compilePlan(
  tenantId: number,
  deviceId: number,
  opts: CompileOptions = {},
): Promise<PlanCompilation> {
  const q = opts.trx ?? db;
  const warnings: string[] = [];

  const device = await loadDevice(tenantId, deviceId, q);

  // ── 1. The DESIRED side ──────────────────────────────────────────────────
  const renderOpts: RenderOptions = {
    persist: opts.persistRender !== false,
    revisionId: opts.revisionId ?? null,
    createdBy: opts.createdBy ?? null,
    trx: q,
  };
  const render = await renderRevisionForDevice(tenantId, deviceId, renderOpts);
  if (render.status !== 'ok' || !render.ncmDesired) {
    throw new PlanCompilationError(
      `Cannot compile a plan for device #${deviceId}: the template render failed. ` +
        `${render.errorMessage ?? 'no reason recorded'}`,
      render.errorKind ?? 'render_failed',
    );
  }
  warnings.push(...render.warnings);

  // ── 2. The OBSERVED side ─────────────────────────────────────────────────
  const observedRow = await loadObserved(tenantId, deviceId, opts.snapshotId ?? null, q);
  if (!observedRow) {
    throw new PlanCompilationError(
      `Device #${deviceId} has no configuration snapshot. A plan compiled against no observed ` +
        'state would propose to create the entire configuration, including what is already ' +
        'there. Collect the configuration first.',
      'no_snapshot',
    );
  }
  const observed = observedRow.doc;

  // ── 3. The semantic diff — reused, never re-implemented ──────────────────
  //
  // `claimedKinds` is what makes `managed_only` usable for a plan: inside a
  // section the template claims, an observed record we did not write is still
  // `extra`. Outside it, it is inventoried and left alone (§5.3 / Q2).
  const diff = semanticDiff(render.ncmDesired, observed, {
    scope: 'managed_only',
    claimedKinds: new Set(render.claimedKinds),
    fuzzy: true,
  });

  // `baseStateHash` comes from the report, not from a second `ncmHash()` call:
  // one hash, computed once, by the code that did the comparison.
  const baseStateHash = diff.baseStateHash;

  // ── 4. Findings -> ops ───────────────────────────────────────────────────
  const facts = buildMgmtPathFacts(observed, { deviceId, tunnelIp: device.tunnel_ip });
  const built = buildOps(render.ncmDesired, observed, diff, facts, new Set(render.claimedKinds));
  warnings.push(...built.warnings);

  const ops = built.ops;
  const risk = planRisk(ops);

  const plan: ApplyPlan = {
    planUuid: crypto.randomUUID(),
    deviceId,
    source: opts.source ?? DEFAULT_SOURCE,
    ncmVersion: observed.ncmVersion,
    semKeyGeneration: observed.semKeyGeneration,
    baseStateHash,
    ops,
    riskLevel: risk,
    // §6.4. M5 has no forwarding engine, therefore M5 may not claim `accept`.
    mgmtPathVerdict: 'indeterminate',
    blastRadius: buildBlastRadius(device, ops, built.signals),
    expiresAt: new Date(Date.now() + PLAN_TTL_MS).toISOString(),
    orderConverges: built.orderConverges,
  };

  return {
    plan,
    detail: {
      deviceName: device.name,
      renderId: render.renderId,
      revisionId: render.revisionId,
      revision: render.revision,
      templateId: render.templateId,
      observedSnapshotId: observedRow.id,
      observedCapturedAt: observed.capturedAt,
      claimedKinds: render.claimedKinds,
      diff,
      signals: built.signals,
      deletionsBlocked: built.deletionsBlocked,
      warnings,
    },
  };
}

/**
 * Compile a plan for several devices — the rollout preview of M7, and the
 * milestone's own recipe (a): one template on ten devices produces ten plans,
 * each with ITS device's variables.
 *
 * Sequential on purpose. Each compilation renders in a worker with a 5 s
 * ceiling and reads two documents; running 300 of them concurrently would put
 * 300 workers on the API host. `p-limit` is already a dependency and belongs
 * here the day the fleet numbers make it necessary — but the correct
 * concurrency is a measurement, not a guess, and this milestone has not made
 * that measurement.
 */
export interface FleetCompilation {
  plans: PlanCompilation[];
  failures: { deviceId: number; deviceName: string | null; reason: string; message: string }[];
}

export async function compileForDevices(
  tenantId: number,
  deviceIds: readonly number[],
  opts: CompileOptions = {},
): Promise<FleetCompilation> {
  const plans: PlanCompilation[] = [];
  const failures: FleetCompilation['failures'] = [];

  for (const deviceId of deviceIds) {
    try {
      plans.push(await compilePlan(tenantId, deviceId, opts));
    } catch (err) {
      const name = await deviceNameOf(tenantId, deviceId, opts.trx ?? db);
      failures.push({
        deviceId,
        deviceName: name,
        reason: err instanceof PlanCompilationError ? err.reason : (err as Error).name,
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }
  return { plans, failures };
}

async function deviceNameOf(
  tenantId: number,
  deviceId: number,
  q: Knex | Knex.Transaction,
): Promise<string | null> {
  const row = (await q('devices').where({ id: deviceId, tenant_id: tenantId }).first('name')) as
    | { name: string }
    | undefined;
  return row?.name ?? null;
}

async function loadObserved(
  tenantId: number,
  deviceId: number,
  snapshotId: string | null,
  q: Knex | Knex.Transaction,
): Promise<{ id: string; doc: NcmDocument } | null> {
  if (snapshotId) {
    // Tenant scoping goes THROUGH `devices`: `config_snapshots` has no tenant
    // column, exactly like the ten `ncm_*` tables and the SNMP series.
    const row = (await q('config_snapshots as s')
      .join('devices as d', 'd.id', 's.device_id')
      .where('s.id', snapshotId)
      .where('d.tenant_id', tenantId)
      .where('s.device_id', deviceId)
      .first('s.id as id', 's.ncm as ncm')) as { id: string; ncm: unknown } | undefined;
    if (!row) return null;
    return { id: String(row.id), doc: upgradeNcm(row.ncm) };
  }
  const latest = await latestDocument(deviceId);
  return latest ? { id: latest.id, doc: latest.doc } : null;
}

// ============================================================================
// Freshness — guarantee 2
// ============================================================================

export interface FreshnessVerdict {
  fresh: boolean;
  expired: boolean;
  deviceId: number;
  baseStateHash: string;
  currentStateHash: string | null;
  expiresAt: string;
  reason: string | null;
}

/**
 * Is this plan still a statement about the device as it is NOW?
 *
 * Non-throwing sibling of `assertPlanFresh`, for a screen that wants to show a
 * banner rather than an error. Both read the same two facts and there is no
 * third implementation anywhere: M6's executor must call `assertPlanFresh` on a
 * FRESH snapshot taken immediately before the write, and that call is the last
 * line of defence against applying to a box somebody edited.
 */
export async function checkPlanFreshness(
  tenantId: number,
  plan: Pick<ApplyPlan, 'deviceId' | 'baseStateHash' | 'expiresAt'>,
  q: Knex | Knex.Transaction = db,
): Promise<FreshnessVerdict> {
  // Tenant scoping first: a plan carrying another tenant's deviceId must not
  // even reveal whether that device has a snapshot.
  await loadDevice(tenantId, plan.deviceId, q);

  const latest = await latestDocument(plan.deviceId);
  const current = latest ? ncmHash(latest.doc) : null;
  const expired = Date.parse(plan.expiresAt) <= Date.now();
  const fresh = current !== null && current === plan.baseStateHash && !expired;

  let reason: string | null = null;
  if (current === null) reason = 'the device no longer has a configuration snapshot';
  else if (current !== plan.baseStateHash) reason = 'the device configuration changed since the plan was compiled';
  else if (expired) reason = 'the plan expired';

  return {
    fresh,
    expired,
    deviceId: plan.deviceId,
    baseStateHash: plan.baseStateHash,
    currentStateHash: current,
    expiresAt: plan.expiresAt,
    reason,
  };
}

/** Throwing form. THE function M6 must call before touching an equipment. */
export async function assertPlanFresh(
  tenantId: number,
  plan: Pick<ApplyPlan, 'deviceId' | 'baseStateHash' | 'expiresAt'>,
  q: Knex | Knex.Transaction = db,
): Promise<void> {
  const verdict = await checkPlanFreshness(tenantId, plan, q);
  if (verdict.currentStateHash !== plan.baseStateHash) {
    throw new StalePlanError(plan.deviceId, plan.baseStateHash, verdict.currentStateHash);
  }
  if (verdict.expired) throw new PlanExpiredError(plan.deviceId, plan.expiresAt);
}

// ============================================================================
// Findings -> ops
// ============================================================================

interface BuildResult {
  ops: PlanOp[];
  signals: Record<number, RiskAssessment>;
  deletionsBlocked: { resource: NcmResourceKind; coverage: string; count: number }[];
  orderConverges: boolean;
  warnings: string[];
}

/** An op before it has a `seq`. `provides` / `requires` are the dependency
 *  edges; `orderGroup` is the chain a `move` belongs to. */
interface DraftOp {
  kind: PlanOpKind;
  resource: NcmResourceKind;
  semKey: string;
  before: NcmResource | null;
  after: NcmResource | null;
  fields: string[];
  chain: string | null;
  targetIndex: number | null;
  blockedReason: PlanOp['blockedReason'];
  finding: NcmDiffFinding | null;
  coverageDegraded: boolean;
  /** Tokens this op makes available (an interface name, a custom chain). */
  provides: string[];
  /** Tokens this op needs to already exist. */
  requires: string[];
  /** Phase, which is the coarse ordering. See `PHASES`. */
  phase: number;
  /** Stable tiebreaker inside a phase, before the graph is applied. */
  rank: number;
}

/**
 * The phases, and why they are in this order.
 *
 *  0 create  — nothing may reference a resource that does not exist yet.
 *  1 update / enable / disable — an update that REMOVES a reference has to run
 *              before the referenced resource is deleted, which is why updates
 *              sit between creates and deletes and not after them.
 *  2 delete  — reverse dependency order inside the phase: a rule that names an
 *              interface is deleted before the interface.
 *  3 move    — computed against the list as it will be AFTER creates and
 *              deletes, so the simulated indices are the real ones (§4.5).
 *  4 verify  — the chain obtained equals the chain desired.
 *  5 blocked — information, not instructions. Last so `seq` order stays
 *              executable from 0 to the first blocked op.
 */
const PHASE_CREATE = 0;
const PHASE_UPDATE = 1;
const PHASE_DELETE = 2;
const PHASE_MOVE = 3;
const PHASE_VERIFY = 4;
const PHASE_BLOCKED = 5;

/**
 * Cross-kind creation layers.
 *
 * An interface is created before a VLAN on it, before a route through it,
 * before a firewall rule that names it. This is a FIXED layering rather than a
 * computed graph because the reference direction between NCM resource kinds is
 * a property of the model, not of a document — and a computed graph would
 * re-derive the same five numbers on every plan while being able to get them
 * wrong.
 */
const CREATE_LAYER: Readonly<Record<NcmResourceKind, number>> = {
  interface: 0,
  vlan: 1,
  ipsecPeer: 2,
  route: 3,
  dhcpScope: 3,
  qosRule: 3,
  firewallRule: 4,
  natRule: 4,
  localUser: 5,
  service: 5,
};

function asResource(v: unknown): NcmResource | null {
  return v && typeof v === 'object' ? (v as NcmResource) : null;
}

/** Tokens a resource makes available to others. */
function providesOf(r: NcmResource | null): string[] {
  if (!r) return [];
  switch (r.kind) {
    case 'interface': return [`iface:${r.name}`];
    case 'vlan': return r.name ? [`iface:${r.name}`] : [];
    case 'firewallRule':
      return r.chain === 'custom' && r.chainName ? [`chain:${r.chainName}`] : [];
    case 'natRule':
      return r.chain === 'custom' && r.chainName ? [`natchain:${r.chainName}`] : [];
    default: return [];
  }
}

/** Interface tokens named by a selector. `ifaceList:` is NOT a dependency: an
 *  interface list is not modelled as a resource, so there is nothing to create
 *  and pretending otherwise would produce an unsatisfiable edge. */
function ifaceTokens(sel: Selector | null | undefined): string[] {
  if (!sel) return [];
  const out: string[] = [];
  for (const atom of sel) {
    if (atom.startsWith('iface:')) out.push(atom);
  }
  return out;
}

/** Tokens a resource needs before it can exist. */
function requiresOf(r: NcmResource | null): string[] {
  if (!r) return [];
  const out = new Set<string>();
  switch (r.kind) {
    case 'interface':
      if (r.parent) out.add(`iface:${r.parent}`);
      break;
    case 'vlan':
      if (r.parent) out.add(`iface:${r.parent}`);
      for (const p of r.taggedPorts) out.add(`iface:${p}`);
      for (const p of r.untaggedPorts) out.add(`iface:${p}`);
      break;
    case 'route':
      if (r.gateway?.startsWith('iface:')) out.add(r.gateway);
      break;
    case 'dhcpScope':
      if (r.onInterface.startsWith('iface:')) out.add(r.onInterface);
      break;
    case 'firewallRule':
      for (const t of ifaceTokens(r.match.inInterface)) out.add(t);
      for (const t of ifaceTokens(r.match.outInterface)) out.add(t);
      // A `jump` needs its target chain to exist. On RouterOS a chain exists
      // because a rule carries it, so this edge is "the target chain's rules
      // first" — which is exactly what `provides` above expresses.
      if (r.action === 'jump' && r.jumpTarget) out.add(`chain:${r.jumpTarget}`);
      break;
    case 'natRule':
      for (const t of ifaceTokens(r.match.inInterface)) out.add(t);
      for (const t of ifaceTokens(r.match.outInterface)) out.add(t);
      break;
    case 'qosRule':
      for (const t of ifaceTokens(r.target)) out.add(t);
      if (r.parent) out.add(`iface:${r.parent}`);
      break;
    default:
      break;
  }
  return [...out];
}

function chainOf(r: NcmResource | null): string | null {
  if (!r) return null;
  if (r.kind === 'firewallRule' || r.kind === 'natRule') {
    return r.chainName ? `${r.chain}:${r.chainName}` : r.chain;
  }
  if (r.kind === 'qosRule') return r.queueClass;
  return null;
}

function buildOps(
  desired: NcmDocument,
  observed: NcmDocument,
  diff: NcmDiffReport,
  facts: MgmtPathFacts,
  claimed: ReadonlySet<NcmResourceKind>,
): BuildResult {
  const drafts: DraftOp[] = [];
  const warnings: string[] = [];
  const deletionsBlocked = new Map<NcmResourceKind, { coverage: string; count: number }>();
  let rank = 0;

  const degradedKinds = new Set<NcmResourceKind>();
  for (const kind of NCM_RESOURCE_KINDS) {
    if (coverageOf(observed.coverage, kind).state !== 'complete') degradedKinds.add(kind);
  }

  for (const finding of diff.findings) {
    const kind = finding.resource;
    const intent = asResource(finding.intentValue);
    const actual = asResource(finding.actualValue);
    const degraded = degradedKinds.has(kind);

    switch (finding.kind) {
      case 'missing': {
        // Present in the desired state, absent from the device -> create it.
        if (!intent) break;
        drafts.push({
          kind: 'create', resource: kind, semKey: finding.semKey,
          before: null, after: intent, fields: [],
          chain: chainOf(intent), targetIndex: null, blockedReason: null,
          finding, coverageDegraded: degraded,
          provides: providesOf(intent), requires: requiresOf(intent),
          phase: PHASE_CREATE, rank: rank++,
        });
        break;
      }

      case 'extra': {
        // ── N3, GUARANTEE 1 ───────────────────────────────────────────────
        //
        // The device carries something the template does not. Removing it is
        // the correct instruction ONLY if we know we saw everything. If the
        // collection for this kind was partial, failed or unsupported, we do
        // not know that, and a delete compiled from an incomplete picture is
        // how a truncated export empties a firewall.
        if (!actual) break;
        const coverage = coverageOf(observed.coverage, kind);
        if (coverage.state !== 'complete') {
          const entry = deletionsBlocked.get(kind) ?? { coverage: coverage.state, count: 0 };
          entry.count += 1;
          deletionsBlocked.set(kind, entry);
          drafts.push({
            kind: 'blocked', resource: kind, semKey: finding.semKey,
            before: actual, after: null, fields: [],
            chain: chainOf(actual), targetIndex: null,
            blockedReason: 'coverage_incomplete',
            finding, coverageDegraded: true,
            provides: [], requires: [],
            phase: PHASE_BLOCKED, rank: rank++,
          });
          break;
        }
        drafts.push({
          kind: 'delete', resource: kind, semKey: finding.semKey,
          before: actual, after: null, fields: [],
          chain: chainOf(actual), targetIndex: null, blockedReason: null,
          finding, coverageDegraded: degraded,
          // A delete REMOVES the tokens it provided; the reverse ordering below
          // reads `provides` as "what disappears", which is why the same field
          // serves both directions.
          provides: providesOf(actual), requires: [],
          phase: PHASE_DELETE, rank: rank++,
        });
        break;
      }

      case 'changed': {
        if (!intent || !actual) break;
        const fields = finding.fieldDiffs.map((f) => f.field);
        // A change whose ONLY field is `disabled` is an enable/disable, not an
        // update. The distinction is not cosmetic: on RouterOS the two are
        // different commands, and M6's executor dispatches on `kind`.
        const onlyDisabled = fields.length === 1 && fields[0] === 'disabled';
        const kindOp: PlanOpKind = onlyDisabled
          ? (intent.disabled ? 'disable' : 'enable')
          : 'update';
        drafts.push({
          kind: kindOp, resource: kind, semKey: finding.semKey,
          before: actual, after: intent, fields,
          chain: chainOf(intent), targetIndex: null, blockedReason: null,
          finding, coverageDegraded: degraded,
          provides: providesOf(intent),
          // An update can ADD a reference (a rule that starts naming a new
          // interface), so its requirements are the DESIRED ones.
          requires: requiresOf(intent),
          phase: PHASE_UPDATE, rank: rank++,
        });
        break;
      }

      case 'moved':
        // Handled wholesale by the move simulation below: a `moved` finding
        // says a rule crossed something, not where it must end up, and §4.5 is
        // explicit that moves computed independently of one another produce a
        // wrong final order.
        break;

      default:
        break;
    }
  }

  // ── Moves, against a SIMULATED list, chain by chain (§4.5) ──────────────
  const moveResult = buildMoveOps(desired, observed, diff, drafts, degradedKinds);
  drafts.push(...moveResult.drafts);
  warnings.push(...moveResult.warnings);
  for (let i = 0; i < moveResult.drafts.length; i++) moveResult.drafts[i].rank = rank++;

  // ── Suppressions the diff declared, surfaced as blocked ops ─────────────
  //
  // ONLY for kinds the template CLAIMS. A `firewallRule` suppression on a
  // template that writes the firewall is information the operator needs; a
  // `qosRule` suppression on a template that never mentioned queues is not a
  // blockage at all — it is the scope working as designed, and emitting it
  // would put eight grey rows under every plan in the product. That is R3
  // applied to the plan screen: where completeness and quiet conflict, quiet
  // wins and the gap stays COUNTED (`detail.diff.suppressed` carries the full
  // list either way).
  for (const s of diff.suppressed) {
    if (!claimed.has(s.resource)) continue;
    if (s.reason === 'coverage_incomplete' && deletionsBlocked.has(s.resource)) continue;
    drafts.push({
      kind: 'blocked', resource: s.resource, semKey: `suppressed:${s.resource}`,
      before: null, after: null, fields: [], chain: null, targetIndex: null,
      blockedReason: suppressionToBlockReason(s.reason),
      finding: null, coverageDegraded: s.reason === 'coverage_incomplete',
      provides: [], requires: [], phase: PHASE_BLOCKED, rank: rank++,
    });
  }

  // ── Ordering ────────────────────────────────────────────────────────────
  const ordered = orderDrafts(drafts, warnings);

  // ── Scoring and materialisation ─────────────────────────────────────────
  const signals: Record<number, RiskAssessment> = {};
  const ops: PlanOp[] = [];
  const seqByProvidedToken = new Map<string, number>();

  ordered.forEach((draft, seq) => {
    const assessment = scoreOp({
      kind: draft.kind,
      resource: draft.resource,
      before: draft.before,
      after: draft.after,
      fields: draft.fields,
      finding: draft.finding,
      facts,
      coverageDegraded: draft.coverageDegraded,
    });
    signals[seq] = assessment;

    const dependsOn: number[] = [];
    if (draft.kind !== 'blocked') {
      for (const token of draft.requires) {
        const producer = seqByProvidedToken.get(token);
        if (producer !== undefined && producer !== seq) dependsOn.push(producer);
      }
      // A move — and the `verify` that closes a chain — can only run once the
      // chain's POPULATION is final: `targetIndex` was computed against the
      // list as it will be after every create and every delete, and running a
      // move before them would land the rule at an index that means something
      // else.
      //
      // The comparison is on (resource, chain), not on chain alone: a firewall
      // `custom` chain and a NAT `custom` chain can carry the same name, they
      // are two different lists on the device, and an op in one must not gate
      // an op in the other.
      if (draft.kind === 'move' || draft.kind === 'verify') {
        for (let s = 0; s < seq; s++) {
          const prior = ordered[s];
          if (prior.kind === 'move' || prior.kind === 'verify' || prior.kind === 'blocked') continue;
          if (prior.resource === draft.resource && prior.chain === draft.chain) dependsOn.push(s);
        }
      }
    }

    ops.push({
      seq,
      kind: draft.kind,
      resource: draft.resource,
      semKey: draft.semKey.slice(0, 180),
      risk: draft.kind === 'blocked' ? 'low' : assessment.risk,
      before: draft.before,
      after: draft.after,
      fields: draft.fields.map((f) => f.slice(0, 120)),
      chain: draft.chain === null ? null : draft.chain.slice(0, 80),
      targetIndex: draft.targetIndex,
      dependsOn: [...new Set(dependsOn)].sort((a, b) => a - b),
      blockedReason: draft.blockedReason,
      reason: blockedSentence(draft) ?? assessment.reason,
      disruptive: assessment.disruptive,
    });

    if (draft.kind === 'create' || draft.kind === 'update') {
      for (const token of draft.provides) seqByProvidedToken.set(token, seq);
    }
  });

  return {
    ops,
    signals,
    deletionsBlocked: [...deletionsBlocked].map(([resource, v]) => ({
      resource, coverage: v.coverage, count: v.count,
    })),
    orderConverges: moveResult.converges,
    warnings,
  };
}

function suppressionToBlockReason(reason: string): PlanOp['blockedReason'] {
  switch (reason) {
    case 'version_skew': return 'version_skew';
    case 'weak_keys': return 'weak_key';
    case 'order_partial': return 'coverage_incomplete';
    default: return 'coverage_incomplete';
  }
}

/** A `blocked` op's sentence explains the refusal, not the risk. It is the one
 *  place in the product where an operator finds out WHY a change they asked for
 *  did not become an instruction — a greyed-out button with no reason is how a
 *  guard gets routed around. */
function blockedSentence(draft: DraftOp): string | null {
  if (draft.kind !== 'blocked') return null;
  switch (draft.blockedReason) {
    case 'coverage_incomplete':
      if (draft.before) {
        return (
          `REFUSED — this ${draft.resource} exists on the device and not in the template, but ` +
          `the configuration collection for ${draft.resource} is not complete, so ObliWAN ` +
          'cannot prove it saw everything. No deletion is compiled from an incomplete ' +
          'collection (N3). Re-collect the configuration, then recompile.'
        ).slice(0, 400);
      }
      return (
        `REFUSED — ${draft.resource} was not compared: the collection for this resource kind ` +
        'is incomplete or its ordering could not be established. Nothing is claimed about it.'
      ).slice(0, 400);
    case 'weak_key':
      return (
        `REFUSED — every ${draft.resource} record on this device has an identity too weak to ` +
        'pair reliably. Acting on a coin-flip pairing would change the wrong record.'
      ).slice(0, 400);
    case 'version_skew':
      return (
        `REFUSED — the desired and observed documents use different NCM versions and were not ` +
        'compared. Re-collect the configuration so both sides speak the same model.'
      ).slice(0, 400);
    default:
      return `REFUSED — ${draft.resource}: ${draft.blockedReason ?? 'unspecified'}.`;
  }
}

// ============================================================================
// Ordering
// ============================================================================

/**
 * Order the drafts so that `dependsOn` is satisfiable in `seq` order.
 *
 * ┌─ REUSE, AND ITS ONE LIMIT, STATED PLAINLY ──────────────────────────────┐
 * │ `utils/topoSort.ts` sorts a PARENT-REFERENCING list — each item has at   │
 * │ most one parent — with real cycle detection. That is exactly the shape   │
 * │ of the interface hierarchy (a VLAN on a bridge on an ethernet port), and │
 * │ that is where it is used below, cycle detection included: a bridge whose │
 * │ parent chain closes on itself is a template bug, and `CycleError` names  │
 * │ the members instead of ordering them arbitrarily.                        │
 * │                                                                          │
 * │ It CANNOT express the rest: a firewall rule depends on its in-interface, │
 * │ its out-interface AND its jump target — three parents. A single-parent   │
 * │ sort would have to drop two of the three edges, and a dropped edge is a  │
 * │ plan that references something that does not exist yet.                  │
 * │                                                                          │
 * │ So the cross-kind order is a FIXED LAYERING (`CREATE_LAYER`) rather than │
 * │ a second graph algorithm: interfaces before VLANs before routes before   │
 * │ firewall rules. The layering is a property of the NCM model, it is five  │
 * │ numbers, and it is reviewable — which a hand-rolled Kahn implementation  │
 * │ with its own cycle handling would not be.                                │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
function orderDrafts(drafts: DraftOp[], warnings: string[]): DraftOp[] {
  const byPhase = new Map<number, DraftOp[]>();
  for (const d of drafts) {
    const list = byPhase.get(d.phase);
    if (list) list.push(d);
    else byPhase.set(d.phase, [d]);
  }

  const out: DraftOp[] = [];
  for (const phase of [PHASE_CREATE, PHASE_UPDATE, PHASE_DELETE, PHASE_MOVE, PHASE_VERIFY, PHASE_BLOCKED]) {
    const list = byPhase.get(phase) ?? [];
    if (phase === PHASE_CREATE) out.push(...orderCreates(list, warnings));
    else if (phase === PHASE_DELETE) out.push(...orderDeletes(list, warnings));
    else out.push(...list.sort((a, b) => a.rank - b.rank));
  }
  return out;
}

/** Interface-shaped drafts, as `topoSort` wants them: a key and a parent key. */
interface HierarchyItem extends Record<string, unknown> {
  key: string;
  parent: string;
  draft: DraftOp;
}

function orderCreates(list: DraftOp[], warnings: string[]): DraftOp[] {
  // 1. Within the interface layer, the parent chain decides. THIS is topoSort's
  //    shape, and its cycle detection is the point.
  const hierarchy = list.filter((d) => CREATE_LAYER[d.resource] <= 1);
  const rest = list.filter((d) => CREATE_LAYER[d.resource] > 1);

  let orderedHierarchy: DraftOp[];
  if (hierarchy.length > 1) {
    const items: HierarchyItem[] = hierarchy.map((draft) => ({
      key: providesOf(draft.after)[0] ?? `op:${draft.semKey}`,
      // A parent outside `items` is an anchor already on the device: topoSort
      // treats it as a root, which is exactly right.
      parent: requiresOf(draft.after).find((t) => t.startsWith('iface:')) ?? '',
      draft,
    }));
    try {
      orderedHierarchy = topoSort(items, 'key', 'parent').map((i) => i.draft);
    } catch (err) {
      if (err instanceof CycleError) {
        warnings.push(
          `The desired interface hierarchy contains a cycle (${err.cycle.join(' -> ')}). ` +
            'The creation order for those interfaces is the template\'s own order and may be ' +
            'wrong; fix the template rather than approving this plan.',
        );
        const cyclic = findCycles(items, 'key', 'parent');
        if (cyclic.length > 0) {
          warnings.push(`Interfaces on a cycle: ${cyclic.sort().join(', ')}.`);
        }
        orderedHierarchy = hierarchy.slice().sort((a, b) => a.rank - b.rank);
      } else {
        throw err;
      }
    }
  } else {
    orderedHierarchy = hierarchy;
  }

  // 2. Everything else follows the fixed layering, then the input order.
  rest.sort((a, b) => CREATE_LAYER[a.resource] - CREATE_LAYER[b.resource] || a.rank - b.rank);

  // 3. Inside the firewall layer, custom chains first: a rule that jumps into a
  //    chain needs the chain's rules to exist. One pass, deterministic.
  const providers: DraftOp[] = [];
  const consumers: DraftOp[] = [];
  for (const d of rest) {
    if (d.provides.some((t) => t.startsWith('chain:') || t.startsWith('natchain:'))) providers.push(d);
    else consumers.push(d);
  }

  return [...orderedHierarchy, ...providers, ...consumers];
}

/**
 * Deletes run in REVERSE dependency order: whatever names a resource is removed
 * before the resource itself.
 *
 * The reverse of the creation layering is exactly that, for the same reason the
 * layering is right in the first place — the reference direction between kinds
 * is a property of the model. Inside a layer, the interface hierarchy is
 * reversed too: a VLAN goes before the bridge it sits on.
 */
function orderDeletes(list: DraftOp[], warnings: string[]): DraftOp[] {
  const hierarchy = list.filter((d) => CREATE_LAYER[d.resource] <= 1);
  const rest = list.filter((d) => CREATE_LAYER[d.resource] > 1);

  rest.sort((a, b) => CREATE_LAYER[b.resource] - CREATE_LAYER[a.resource] || a.rank - b.rank);

  let orderedHierarchy: DraftOp[] = hierarchy;
  if (hierarchy.length > 1) {
    const items: HierarchyItem[] = hierarchy.map((draft) => ({
      key: providesOf(draft.before)[0] ?? `op:${draft.semKey}`,
      parent: requiresOf(draft.before).find((t) => t.startsWith('iface:')) ?? '',
      draft,
    }));
    try {
      orderedHierarchy = topoSort(items, 'key', 'parent').map((i) => i.draft).reverse();
    } catch (err) {
      if (err instanceof CycleError) {
        warnings.push(
          `The observed interface hierarchy contains a cycle (${err.cycle.join(' -> ')}); ` +
            'the deletion order for those interfaces is not proven safe.',
        );
        orderedHierarchy = hierarchy.slice().sort((a, b) => b.rank - a.rank);
      } else {
        throw err;
      }
    }
  }

  return [...rest, ...orderedHierarchy];
}

// ============================================================================
// Moves — §4.5, the trap
// ============================================================================

interface MoveBuild {
  drafts: DraftOp[];
  converges: boolean;
  warnings: string[];
}

/**
 * `/ip/firewall/filter/move numbers=X destination=Y` RENUMBERS the list on
 * every move. A sequence of moves computed independently of one another
 * produces a wrong final order — §4.5 names this as the implementation trap of
 * this milestone.
 *
 * So the moves are generated AGAINST A SIMULATION, op by op:
 *   1. build the list as it will be after the creates and the deletes;
 *   2. walk the target order left to right;
 *   3. whenever the simulated list disagrees, emit ONE move that puts the right
 *      rule at that index, then MUTATE the simulation and continue.
 * `targetIndex` is therefore the index in the list AS IT IS WHEN THAT OP RUNS,
 * never the index in the original document.
 *
 * The plan then ends with a `verify` op per chain asserting the obtained chain
 * equals the desired chain, and `orderConverges` says whether the simulation
 * actually got there. A plan with `move` ops and `orderConverges: false` must
 * not be offered for approval — the contract says so, and the flag is the only
 * way a reviewer could know.
 *
 * NOTE on the RouterOS off-by-one: `destination` on RouterOS is "before the
 * item currently numbered Y", and moving an item DOWN the list shifts the
 * target by one. That translation belongs to the driver at apply time (M6),
 * which is also the only place that knows the live `.id` values. `targetIndex`
 * here is brand-neutral: "this resource must sit at index N of its chain".
 */
function buildMoveOps(
  desired: NcmDocument,
  observed: NcmDocument,
  diff: NcmDiffReport,
  existing: DraftOp[],
  degradedKinds: ReadonlySet<NcmResourceKind>,
): MoveBuild {
  const drafts: DraftOp[] = [];
  const warnings: string[] = [];
  let converges = true;

  // Alias: a pairing may join two records whose semKeys differ (marker or fuzzy
  // pairing). The simulation speaks in OBSERVED tokens, so every desired rule
  // is translated through the pairing the diff actually made.
  const alias = new Map<string, string>();
  for (const f of diff.findings) {
    const intent = asResource(f.intentValue);
    const actual = asResource(f.actualValue);
    if (intent && actual && intent.semKey !== actual.semKey) alias.set(intent.semKey, actual.semKey);
  }

  const deleted = new Set(existing.filter((d) => d.kind === 'delete').map((d) => d.semKey));
  const created = new Map<string, DraftOp>();
  for (const d of existing) if (d.kind === 'create') created.set(d.semKey, d);

  const orderSuppressed = new Set(
    diff.suppressed.filter((s) => s.reason === 'order_partial' || s.reason === 'weak_keys')
      .map((s) => s.resource),
  );

  for (const kind of ORDERED_RESOURCE_KINDS) {
    if (orderSuppressed.has(kind)) {
      drafts.push({
        kind: 'blocked', resource: kind, semKey: `order:${kind}`,
        before: null, after: null, fields: ['order'], chain: null, targetIndex: null,
        blockedReason: 'coverage_incomplete', finding: null, coverageDegraded: true,
        provides: [], requires: [], phase: PHASE_BLOCKED, rank: 0,
      });
      continue;
    }

    const desiredRules = rulesOf(desired, kind);
    const observedRules = rulesOf(observed, kind);
    if (desiredRules.length === 0) continue;

    const chains = new Set<string>();
    for (const r of desiredRules) chains.add(chainOf(r) ?? '');

    for (const chain of [...chains].sort()) {
      // The simulated list: observed rules of this chain, minus the ones the
      // plan deletes, plus the ones it creates (RouterOS `add` appends).
      const simulated: string[] = observedRules
        .filter((r) => (chainOf(r) ?? '') === chain && !deleted.has(r.semKey))
        .map((r) => r.semKey);
      const byToken = new Map<string, NcmResource>();
      for (const r of observedRules) byToken.set(r.semKey, r);

      const desiredInChain = desiredRules.filter((r) => (chainOf(r) ?? '') === chain);
      for (const r of desiredInChain) {
        const token = alias.get(r.semKey) ?? r.semKey;
        if (created.has(r.semKey) && !simulated.includes(token)) {
          simulated.push(token);
          byToken.set(token, r);
        }
      }

      const target = desiredInChain
        .map((r) => alias.get(r.semKey) ?? r.semKey)
        .filter((t) => simulated.includes(t));

      // Rules present on the box that the template did not claim keep their
      // relative position. They are appended to the target so the simulation
      // has somewhere to put them, in their observed order, AFTER the claimed
      // ones — which is the only choice that does not reorder configuration
      // nobody asked us to touch.
      const claimedSet = new Set(target);
      for (const token of simulated) if (!claimedSet.has(token)) target.push(token);

      if (target.length !== simulated.length) {
        // Cannot happen through the construction above; if it ever did, a move
        // sequence computed from it would be wrong, and a wrong move sequence
        // is worse than no move at all.
        converges = false;
        warnings.push(
          `Order simulation for ${kind} chain "${chain}" is inconsistent ` +
            `(${simulated.length} rules simulated, ${target.length} targeted); no move ` +
            'operation was generated for it.',
        );
        continue;
      }

      const work = simulated.slice();
      for (let i = 0; i < target.length; i++) {
        if (work[i] === target[i]) continue;
        const from = work.indexOf(target[i], i);
        if (from < 0) {
          converges = false;
          warnings.push(
            `Order simulation for ${kind} chain "${chain}" lost rule ${target[i]}; ` +
              'the plan does not prove the final order.',
          );
          break;
        }
        const [token] = work.splice(from, 1);
        work.splice(i, 0, token);
        const resource = byToken.get(token) ?? null;
        drafts.push({
          kind: 'move', resource: kind, semKey: token,
          before: resource, after: resource, fields: ['position'],
          chain, targetIndex: i, blockedReason: null,
          finding: diff.findings.find((f) => f.kind === 'moved' && f.semKey === token) ?? null,
          coverageDegraded: degradedKinds.has(kind),
          provides: [], requires: [], phase: PHASE_MOVE, rank: 0,
        });
      }

      const moved = drafts.some((d) => d.kind === 'move' && d.chain === chain && d.resource === kind);
      if (moved) {
        const ok = work.every((t, i) => t === target[i]);
        if (!ok) converges = false;
        drafts.push({
          kind: 'verify', resource: kind, semKey: `order:${kind}:${chain}`,
          before: null, after: null, fields: ['position'],
          chain, targetIndex: null, blockedReason: null,
          finding: null, coverageDegraded: degradedKinds.has(kind),
          provides: [], requires: [], phase: PHASE_VERIFY, rank: 0,
        });
      }
    }
  }

  return { drafts, converges, warnings };
}

function rulesOf(doc: NcmDocument, kind: NcmResourceKind): NcmOrderedRule[] {
  const key = RESOURCE_KIND_TO_COLLECTION[kind] as keyof NcmDocument['resources'];
  return (doc.resources[key] ?? []) as unknown as NcmOrderedRule[];
}

// ============================================================================
// Blast radius
// ============================================================================

function buildBlastRadius(
  device: DeviceRow,
  ops: readonly PlanOp[],
  signals: Record<number, RiskAssessment>,
): BlastRadius {
  const interfaces = new Set<string>();
  const subnets = new Set<string>();
  let touchesManagementPath = false;

  for (const op of ops) {
    if (op.kind === 'blocked') continue;
    if (signals[op.seq]?.tunnelCritical) touchesManagementPath = true;
    for (const side of [op.before, op.after]) {
      const r = asResource(side);
      if (!r) continue;
      switch (r.kind) {
        case 'interface':
          interfaces.add(r.name);
          for (const a of r.addresses) subnets.add(a.cidr);
          break;
        case 'vlan':
          if (r.name) interfaces.add(r.name);
          break;
        case 'route':
          subnets.add(r.dst);
          if (r.gateway?.startsWith('iface:')) interfaces.add(r.gateway.slice('iface:'.length));
          break;
        case 'dhcpScope':
          subnets.add(r.subnet);
          if (r.onInterface.startsWith('iface:')) interfaces.add(r.onInterface.slice('iface:'.length));
          break;
        case 'firewallRule':
        case 'natRule':
          for (const atom of [...r.match.inInterface, ...r.match.outInterface]) {
            if (atom.startsWith('iface:')) interfaces.add(atom.slice('iface:'.length));
          }
          break;
        default:
          break;
      }
    }
  }

  return {
    deviceCount: 1,
    siteCount: device.site_id === null ? 0 : 1,
    // Capped: `BlastRadius` is shown on a screen before launch, and a list of
    // 400 interfaces is not information. The counts above stay exact.
    affectedInterfaces: [...interfaces].filter((s) => s.length <= 64).sort().slice(0, 200),
    affectedSubnets: [...subnets].filter((s) => s.length <= 49).sort().slice(0, 200),
    touchesManagementPath,
  };
}

// ============================================================================
// Summary — what the fleet screen shows without loading every op
// ============================================================================

export interface PlanSummary {
  deviceId: number;
  deviceName: string;
  planUuid: string;
  riskLevel: RiskLevel;
  mgmtPathVerdict: ApplyPlan['mgmtPathVerdict'];
  baseStateHash: string;
  expiresAt: string;
  orderConverges: boolean;
  opCount: number;
  byKind: Record<PlanOpKind, number>;
  blockedCount: number;
  tunnelCriticalCount: number;
  touchesManagementPath: boolean;
}

export function summarize(c: PlanCompilation): PlanSummary {
  const byKind = {
    create: 0, update: 0, delete: 0, move: 0,
    enable: 0, disable: 0, verify: 0, blocked: 0,
  } as Record<PlanOpKind, number>;
  let tunnelCriticalCount = 0;
  for (const op of c.plan.ops) {
    byKind[op.kind] += 1;
    if (c.detail.signals[op.seq]?.tunnelCritical) tunnelCriticalCount += 1;
  }
  return {
    deviceId: c.plan.deviceId,
    deviceName: c.detail.deviceName,
    planUuid: c.plan.planUuid,
    riskLevel: c.plan.riskLevel,
    mgmtPathVerdict: c.plan.mgmtPathVerdict,
    baseStateHash: c.plan.baseStateHash,
    expiresAt: c.plan.expiresAt,
    orderConverges: c.plan.orderConverges,
    opCount: c.plan.ops.length,
    byKind,
    blockedCount: byKind.blocked,
    tunnelCriticalCount,
    touchesManagementPath: c.plan.blastRadius.touchesManagementPath,
  };
}

export const plannerService = {
  compilePlan,
  compileForDevices,
  checkPlanFreshness,
  assertPlanFresh,
  summarize,
  PLAN_TTL_MS,
};

// Re-exported so a caller that already imports the planner does not reach into
// two modules for the same decision.
export { classifyResource, buildMgmtPathFacts };
export type { RenderResultRecord };
