// ============================================================================
// ObliWAN — render.service : a template revision becomes `ncm_desired`
// ============================================================================
//
// ┌─ THE OUTPUT OF THIS FILE IS NOT TEXT ────────────────────────────────────┐
// │ Rendering produces RouterOS text, and that text is a by-product. The     │
// │ useful output is an `NcmDocument` — the DESIRED side — because the       │
// │ planner compares NCM to NCM and never text to text. A textual diff of    │
// │ two exports reports a changed comment as a changed firewall and misses   │
// │ a rule that moved; the whole M4 contract exists so that this milestone   │
// │ never has to do that.                                                    │
// │                                                                          │
// │ So: render -> `parseExport` / `normalizeRouterOsExport` (M4's parser,    │
// │ imported, never re-implemented) -> `NcmDocument`.                        │
// └──────────────────────────────────────────────────────────────────────────┘
//
// ┌─ §8.2, AND IT IS THE HARDEST CONSTRAINT IN THIS FILE ────────────────────┐
// │ The STORED render is the REDACTED one. The complete version — the one    │
// │ with the plaintext secrets — exists in memory only, on the path towards  │
// │ the equipment.                                                           │
// │                                                                          │
// │ At M5 NOTHING GOES TOWARDS AN EQUIPMENT. Applying is M6. Therefore this  │
// │ file has NO function that produces a plaintext-secret render, no `mode`  │
// │ parameter that reaches `buildRenderContext`, and no caller can ask for   │
// │ one: `renderRevisionForDevice` hard-codes `mode: 'redacted'`. When M6    │
// │ needs the complete form it will add a separate, explicitly named         │
// │ function on the push path — and that function must never write to        │
// │ `config_renders`. The redaction is not a filter applied before the       │
// │ INSERT; the plaintext is never produced in the first place. That is the  │
// │ difference between a control and a habit.                                │
// │                                                                          │
// │ Belt and braces anyway: `assertNoPlaintextSecret()` runs on the body     │
// │ before it is persisted, because a template author can hardcode a         │
// │ credential in the template TEXT, where no context redaction can reach.   │
// └──────────────────────────────────────────────────────────────────────────┘
//
// ┌─ N3 ON THE DESIRED SIDE — the guard that keeps a template from emptying  │
// │   a firewall ────────────────────────────────────────────────────────────┤
// │ `normalizeRouterOsExport` was written for a WHOLE `/export`. Handed a    │
// │ template render — which is a FRAGMENT covering two or three sections —   │
// │ it would honestly report `coverage.firewallRule = 'complete'` while the  │
// │ template never mentioned the firewall. The diff engine would then read   │
// │ "the desired state contains no firewall rule, and it claims to be        │
// │ complete", emit an `extra` for every observed rule, and the planner      │
// │ would compile a plan that deletes the site's firewall.                   │
// │                                                                          │
// │ So the coverage of the desired document is REWRITTEN here from what the  │
// │ template actually CLAIMS: a resource kind is `complete` only if the      │
// │ rendered body wrote lines in a section that maps to it, or the revision  │
// │ declared it in `section_severity`. Everything else becomes               │
// │ `unsupported` with a reason the operator can read. `semanticDiff` then   │
// │ suppresses the kind entirely instead of inventing 200 findings.          │
// │                                                                          │
// │ A template that genuinely means "this chain must be EMPTY" says so by    │
// │ declaring the section in `section_severity` — an explicit, auditable     │
// │ gesture — and never by omission.                                         │
// └──────────────────────────────────────────────────────────────────────────┘

import crypto from 'crypto';
import type { Knex } from 'knex';
import type {
  NcmCoverage, NcmCoverageMap, NcmDocument, NcmResourceKind, DeviceFamily,
} from '@obliwan/shared';
import {
  NCM_RESOURCE_KINDS, NcmDocumentAuthored, ncmHash,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { parseExport } from '../drivers/mikrotik/parse';
import { aliasSection, sectionSpec } from '../drivers/mikrotik/quirks';
import {
  loadDefaults, loadNormalizationRules,
  type NormalizeContextInput, type NormalizeFn, type NormalizeOutput,
} from '../config/collect.service';
import { latestDocument } from '../config/snapshot.service';
import { renderTemplate, type RenderErrorKind } from './engine';
import { loadRevisionBundle, loadScratchBundle, type TemplateBundle } from './loader';
import {
  modelMatches, resolveRevisionForDevice, satisfiesOsWindow,
  type AssignmentCandidate, type DeviceTemplateResolution,
} from './assignment.service';
import { getRevision, type RevisionRecord } from './version.service';
import {
  assertNoPlaintextSecret, variableResolver, VariableResolutionError,
  SECRET_PLACEHOLDER_RE,
  type JsonValue, type RenderContext, type ResolvedVariables, type VarSchema, type VariableReport,
} from './variableResolver.service';

// ============================================================================
// The normaliser, late-bound exactly as `collect.service` binds it
// ============================================================================
//
// A STATIC import of `normalize.service` would make the whole plan path fail to
// compile whenever that file — another workstream, another agent — is mid-edit.
// `collect.service` already made that call and documented it; copying the
// mechanism rather than inventing a second one means there is one answer to
// "how does the server reach the parser", not two.
//
// The fail-closed default is the point: with no parser, this file REFUSES to
// produce a document. An empty NCM would read, to the diff engine, as a desired
// state that claims nothing, and to the planner as a device whose entire
// configuration is extra.

let normalizeImpl: NormalizeFn | null = null;
let bindAttempted = false;

/** Test seam. The last registration wins. */
export function registerRenderNormalizer(fn: NormalizeFn | null): void {
  normalizeImpl = fn;
  bindAttempted = fn !== null;
}

function bindNormalizer(): NormalizeFn | null {
  if (bindAttempted) return normalizeImpl;
  bindAttempted = true;
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const mod = require('../config/normalize.service') as Record<string, unknown>;
    const fn = mod.normalizeRouterOsExport ?? mod.normalize;
    if (typeof fn === 'function') normalizeImpl = fn as NormalizeFn;
  } catch (err) {
    logger.warn({ err }, 'render.service could not bind the NCM normaliser');
    normalizeImpl = null;
  }
  return normalizeImpl;
}

export class NoParserError extends Error {
  constructor(readonly brand: string) {
    super(
      `No NCM parser is available for brand "${brand}". Refusing to produce a desired ` +
        'document: an empty NCM would read, to the planner, as a device whose entire ' +
        'configuration is extra, and the resulting plan would delete it.',
    );
    this.name = 'NoParserError';
  }
}

/** M5 renders RouterOS and nothing else — `templates.brand` is NOT NULL for
 *  exactly that reason, and the multi-dialect path (K4) compiles from Intent to
 *  NCM, never from a template body. A non-mikrotik brand fails LOUDLY here. */
const RENDERABLE_BRANDS = new Set(['mikrotik']);

// ============================================================================
// Errors
// ============================================================================

export class RenderTargetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RenderTargetError';
  }
}

/** Thrown when a revision may not be rendered onto this device: archived
 *  template, quarantined revision, OS window, wrong brand. Distinct from a
 *  render FAILURE, which is recorded rather than thrown. */
export class RenderRefusedError extends Error {
  constructor(message: string, readonly reason: string) {
    super(message);
    this.name = 'RenderRefusedError';
  }
}

// ============================================================================
// Types
// ============================================================================

export type RenderStatus = 'ok' | 'error';

export interface DeviceRow {
  id: number;
  tenant_id: number;
  group_id: number | null;
  site_id: number | null;
  name: string;
  brand: string;
  family: DeviceFamily | null;
  model: string | null;
  serial: string | null;
  os_version: string | null;
  system_identity: string | null;
  ppp_username: string | null;
  tunnel_ip: string | null;
  is_managed: boolean;
}

export interface RenderResultRecord {
  status: RenderStatus;
  /** `config_renders.id`, or null when the render was not persisted (preview). */
  renderId: string | null;
  deviceId: number;
  tenantId: number;
  templateId: string | null;
  revisionId: string;
  revision: number;
  assignmentId: string | null;

  /** REDACTED body. There is no other kind in this file. */
  body: string | null;
  bodySha256: string | null;

  ncmDesired: NcmDocument | null;
  ncmHash: string | null;
  /** The resource kinds this revision CLAIMS. Handed to `semanticDiff` as
   *  `claimedKinds` and to the planner as the N3 whitelist. */
  claimedKinds: NcmResourceKind[];
  /** Sections the template wrote that the NCM model does not cover. Visible,
   *  counted, never silently dropped (N5). */
  unclaimedSections: string[];

  /** Redacted view — this is what `config_renders.variables_snapshot` holds. */
  variables: ResolvedVariables;
  variablesSnapshot: Record<string, unknown>;
  variablesSha256: string;
  secretKeys: string[];

  depsFingerprint: string | null;
  osVersion: string | null;
  durationMs: number;
  warnings: string[];

  errorKind: RenderErrorKind | 'variables' | 'parse' | 'refused' | null;
  errorMessage: string | null;
  /** Present on the preview path so the UI can show every value's origin. */
  variableReport: VariableReport | null;
}

export interface RenderOptions {
  /** Write a `config_renders` row. FALSE for a preview: an authoring preview
   *  is not evidence of an intent and must not become the desired state a plan
   *  is later compiled from. */
  persist?: boolean;
  /** Explicit revision. Omitted -> `assignment.service` resolves it. */
  revisionId?: string | number | null;
  /** Try values without writing them (authoring preview). A SECRET can never be
   *  overridden this way — that would be a plaintext credential in an HTTP
   *  body — and `variableResolver` refuses it independently. */
  overrides?: { key: string; value: JsonValue }[];
  createdBy?: number | null;
  trx?: Knex | Knex.Transaction;
}

// ============================================================================
// Device loading — tenant-scoped, always
// ============================================================================

/** A device id belonging to another tenant DOES NOT EXIST as far as this
 *  service is concerned. Every read below goes through here. */
export async function loadDevice(
  tenantId: number,
  deviceId: number,
  q: Knex | Knex.Transaction = db,
): Promise<DeviceRow> {
  const row = (await q('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first(
      'id', 'tenant_id', 'group_id', 'site_id', 'name', 'brand', 'family', 'model',
      'serial', 'os_version', 'system_identity', 'ppp_username',
      q.raw('host(tunnel_ip) as tunnel_ip'),
      'is_managed',
    )) as DeviceRow | undefined;
  if (!row) throw new RenderTargetError(`Device #${deviceId} does not exist in tenant #${tenantId}.`);
  return row;
}

// ============================================================================
// Claimed sections -> claimed resource kinds
// ============================================================================

/**
 * Which NCM resource kinds this rendered body speaks about.
 *
 * Derived from the SECTIONS the parser saw, not from the records it produced:
 * a template that writes `/ip/firewall/filter` with every rule behind a
 * `{% if %}` that happened to be false still CLAIMS the firewall, and a plan
 * that leaves the observed rules alone would be silently wrong about what the
 * operator asked for.
 *
 * `sectionLineCounts` is the parser's own inventory of what it read — the same
 * map that feeds `unmodeled[]` — so this never drifts from what the normaliser
 * actually processed.
 */
export function claimedKindsOf(
  renderedBody: string,
  sectionSeverity: unknown,
): { kinds: Set<NcmResourceKind>; sections: string[]; unclaimedSections: string[] } {
  const kinds = new Set<NcmResourceKind>();
  const sections: string[] = [];
  const unclaimedSections: string[] = [];

  let seen: Iterable<string> = [];
  try {
    seen = parseExport(renderedBody).sectionLineCounts.keys();
  } catch {
    // A body the parser cannot even tokenise claims nothing. The render itself
    // will fail one step later with a message that says why.
    seen = [];
  }

  for (const raw of seen) {
    const path = aliasSection(raw);
    sections.push(path);
    const kind = sectionSpec(path)?.ncmResourceKind ?? null;
    if (kind) kinds.add(kind);
    else unclaimedSections.push(path);
  }

  // An explicit declaration in `section_severity` claims the section even when
  // the render emitted no line for it. This is the ONLY way to express "this
  // chain must be empty", and it is deliberately explicit: an empty claim is
  // what authorises a `delete`, and authorising a delete by omission is how a
  // typo empties a firewall.
  if (sectionSeverity && typeof sectionSeverity === 'object' && !Array.isArray(sectionSeverity)) {
    for (const key of Object.keys(sectionSeverity as Record<string, unknown>)) {
      const direct = NCM_RESOURCE_KINDS.find((k) => k === key);
      if (direct) { kinds.add(direct); continue; }
      const kind = sectionSpec(aliasSection(key))?.ncmResourceKind ?? null;
      if (kind) { kinds.add(kind); sections.push(aliasSection(key)); }
    }
  }

  return { kinds, sections: [...new Set(sections)].sort(), unclaimedSections: [...new Set(unclaimedSections)].sort() };
}

/**
 * Rewrite the coverage of a DESIRED document so it describes what the template
 * claims rather than what a full `/export` would have claimed.
 *
 * Never UPGRADES a coverage: if the normaliser said `partial` for a claimed
 * kind (RouterOS omits factory-default interfaces from `/export`, so
 * `coverage.interface` is structurally `partial`), that stays `partial`. This
 * function only ever removes claims.
 */
export function restrictCoverage(
  coverage: NcmCoverageMap,
  claimed: ReadonlySet<NcmResourceKind>,
): NcmCoverageMap {
  const out = {} as Record<NcmResourceKind, NcmCoverage>;
  for (const kind of NCM_RESOURCE_KINDS) {
    const current = coverage[kind];
    if (!current) continue;   // a v2 kind absent from a v1 coverage map
    if (claimed.has(kind)) { out[kind] = current; continue; }
    out[kind] = {
      state: 'unsupported',
      via: current.via,
      reason:
        `This template revision does not write the ${kind} section, so the desired ` +
        'state says nothing about it. No finding and no plan operation may be ' +
        'produced for this resource kind (N3).',
      recordCount: 0,
    };
  }
  return out as NcmCoverageMap;
}

// ============================================================================
// The render
// ============================================================================

function sha256(text: string): string {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

/** The `config_renders.variables_snapshot` shape, per migration 008: a plain
 *  value for a clear variable, a `{secret, fingerprint}` marker for a secret.
 *  The PLAINTEXT never appears — not even for a variable resolved in a mode
 *  this file does not offer. */
export function snapshotOf(variables: ResolvedVariables): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, v] of Object.entries(variables)) {
    out[key] = v.isSecret
      ? { secret: true, fingerprint: v.fingerprint, source: v.source, sourceName: v.sourceName }
      : v.value;
  }
  return out;
}

/** Deterministic hash of the snapshot: `config_renders_dedup_idx` answers
 *  "have I already rendered this revision with these variables for this
 *  device", and that question only has an answer if the hash is canonical. */
function variablesSha(snapshot: Record<string, unknown>): string {
  const keys = Object.keys(snapshot).sort();
  const canonical = JSON.stringify(keys.map((k) => [k, snapshot[k]]));
  return sha256(canonical);
}

/**
 * The device facts a template may read, as ONE nested key.
 *
 * Deliberately not spread as `deviceName`, `deviceModel`, ... at the top level:
 * `buildRenderContext` refuses an `extra` key that collides with an operator
 * variable, so a flat spread would mean that adding a new device fact in a
 * future release BREAKS every tenant who happened to define a variable of that
 * name. One key, one collision surface, and the template writes
 * `{{ device.name }}`.
 *
 * `tunnelIp` is included: a template legitimately needs to write a firewall
 * rule that keeps the management path open, and making it type the address by
 * hand is how the address and the reality drift apart.
 */
function deviceFacts(device: DeviceRow): Record<string, JsonValue> {
  return {
    device: {
      id: device.id,
      name: device.name,
      brand: device.brand,
      family: device.family,
      model: device.model,
      serial: device.serial,
      osVersion: device.os_version,
      systemIdentity: device.system_identity,
      pppUsername: device.ppp_username,
      tunnelIp: device.tunnel_ip,
      siteId: device.site_id,
      groupId: device.group_id,
    } as unknown as JsonValue,
  };
}

interface ResolvedRevision {
  revision: RevisionRecord;
  templateId: string | null;
  assignmentId: string | null;
  candidate: AssignmentCandidate | null;
  resolution: DeviceTemplateResolution | null;
}

/**
 * Which revision applies to this device.
 *
 * An EXPLICIT revisionId is checked against the tenant here — `getRevision`
 * does not scope, by design (a library revision has a NULL tenant), so the
 * scoping is this function's job and it is not optional.
 */
async function resolveRevision(
  tenantId: number,
  device: DeviceRow,
  explicit: string | number | null | undefined,
  q: Knex | Knex.Transaction,
): Promise<ResolvedRevision> {
  if (explicit !== null && explicit !== undefined) {
    const revision = await getRevision(explicit, q);
    if (revision.tenant_id !== null && revision.tenant_id !== tenantId) {
      // Cross-tenant id is a non-existence, not a refusal (config.controller
      // rule 2). The message must not confirm the row exists elsewhere.
      throw new RenderTargetError(`template revision ${explicit} does not exist for this tenant`);
    }
    const template = (await q('templates')
      .where('id', revision.template_id)
      .first('id', 'brand', 'status', 'model_pattern')) as
      { id: string; brand: string; status: string; model_pattern: string | null } | undefined;
    if (!template) throw new RenderTargetError(`template ${revision.template_id} does not exist`);
    if (template.brand !== device.brand) {
      throw new RenderRefusedError(
        `template revision ${explicit} targets ${template.brand} and device #${device.id} is ${device.brand}`,
        'brand_mismatch',
      );
    }
    if (revision.status === 'quarantined') {
      throw new RenderRefusedError(
        `template revision ${explicit} is quarantined and may not be rendered`,
        'revision_quarantined',
      );
    }
    // AUDIT M4/M5 finding F3. `RenderRefusedError` documents four guarantees —
    // "archived template, quarantined revision, OS window, wrong brand" — and
    // this branch applied two of them. `status` was even SELECTed and never
    // read. The three checks below are the missing ones, and they are the same
    // three functions the assignment resolver uses, imported rather than
    // reimplemented: a second implementation of an OS-window comparison is how
    // the two paths start disagreeing about what a device may receive.
    //
    // The branch is reachable with PLAN_CREATE + TEMPLATE_READ alone
    // (`POST /api/plan/devices/:id {revisionId}`, `POST /api/plan/compile`,
    // `POST /api/templates/revisions/:revId/preview`), it PERSISTS a
    // `config_renders` row by default, and the plan it produces is accepted by
    // `POST /api/changes/jobs`. So "revision 9 needs RouterOS 7" was enforced
    // for the fleet and bypassed for anyone who typed the revision id: a
    // `/interface/wifi` body compiled and pushed onto a 6.49 box, or an
    // archived template — the documented gesture for withdrawing a template —
    // still rendering.
    if (template.status !== 'active') {
      throw new RenderRefusedError(
        `template ${revision.template_id} is ${template.status} and may not be rendered`,
        'template_archived',
      );
    }
    if (!modelMatches(template.model_pattern, device.model)) {
      throw new RenderRefusedError(
        `template ${revision.template_id} targets models matching '${template.model_pattern}', ` +
          `device #${device.id} is '${device.model ?? 'unknown'}'`,
        'model_mismatch',
      );
    }
    const os = satisfiesOsWindow(device.os_version, revision.os_min, revision.os_max);
    if (!os.ok) {
      throw new RenderRefusedError(
        `template revision ${explicit} may not be rendered on device #${device.id}: ${os.detail}`,
        os.reason ?? 'os_unknown',
      );
    }
    return { revision, templateId: String(revision.template_id), assignmentId: null, candidate: null, resolution: null };
  }

  const { candidate, resolution } = await resolveRevisionForDevice(tenantId, device.id, { trx: q });
  if (!candidate || !candidate.revisionId) {
    const why = resolution.rejected.length > 0
      ? ` Rejected candidates: ${resolution.rejected.map((r) => `${r.templateName} (${r.reason})`).join(', ')}.`
      : '';
    throw new RenderRefusedError(
      `No template revision resolves for device #${device.id}.${why}`,
      'no_assignment',
    );
  }
  const revision = await getRevision(candidate.revisionId, q);
  return {
    revision,
    templateId: candidate.templateId,
    assignmentId: candidate.assignmentId,
    candidate,
    resolution,
  };
}

/**
 * Render a revision for one device and turn the result into `ncm_desired`.
 *
 * NEVER throws on a template failure — a broken template is DATA, and the
 * operator needs the message, the kind and the row that records it. It throws
 * only when the request itself is wrong: unknown device, cross-tenant id,
 * no applicable revision, brand mismatch, missing parser.
 */
export async function renderRevisionForDevice(
  tenantId: number,
  deviceId: number,
  opts: RenderOptions = {},
): Promise<RenderResultRecord> {
  const q = opts.trx ?? db;
  const started = Date.now();
  const warnings: string[] = [];

  // Declared HERE, before the first `finish()` call, and not at their point of
  // use. `finish()` is a closure over both, and every early-exit path reaches
  // it — including the one that fires BEFORE the bundle is loaded. A `let`
  // declared further down would be in its temporal dead zone at that moment,
  // and reading it throws a ReferenceError that surfaces as a 500 instead of
  // the "this variable has no value" message the operator needs. Found by the
  // verification harness, on the "device with no snapshot" path.
  let ctx: RenderContext | undefined;
  let bundle: TemplateBundle | undefined;

  const device = await loadDevice(tenantId, deviceId, q);
  if (!RENDERABLE_BRANDS.has(device.brand)) {
    throw new RenderRefusedError(
      `Device #${deviceId} is a ${device.brand}; M5 renders RouterOS templates only. ` +
        'The multi-brand path is the Intent Compiler (K4, M11), which compiles Intent -> NCM ' +
        'and never a template body.',
      'brand_unsupported',
    );
  }
  const normalize = bindNormalizer();
  if (!normalize) throw new NoParserError(device.brand);

  const { revision, templateId, assignmentId, resolution } = await resolveRevision(
    tenantId, device, opts.revisionId, q,
  );

  // ── 1. Variables ─────────────────────────────────────────────────────────
  //
  // `mode` is NOT a parameter of this function and never will be. See the §8.2
  // banner at the top of the file.
  try {
    ctx = await variableResolver.buildRenderContext(
      tenantId,
      deviceId,
      (revision.var_schema ?? null) as VarSchema | null,
      {
        groupId: device.group_id,
        mode: 'redacted',
        extra: { ...deviceFacts(device), ...overridesAsExtra(opts.overrides) },
        executor: q,
      },
    );
  } catch (err) {
    if (err instanceof VariableResolutionError) {
      return await finish({
        status: 'error',
        errorKind: 'variables',
        errorMessage: err.message,
        variableReport: await safeReport(tenantId, deviceId, revision, device, q),
      });
    }
    throw err;
  }

  // ── 2. The bundle: pinned partials for a published revision, live for a
  //       draft. `loader.ts` has no code path that reads a partial by NAME for
  //       a non-draft revision, which is what makes "editing a partial does not
  //       change a published render" structural rather than aspirational.
  try {
    bundle = await loadRevisionBundle(revision.id, { trx: q });
  } catch (err) {
    return await finish({
      status: 'error',
      errorKind: 'template',
      errorMessage: err instanceof Error ? err.message : String(err),
      variableReport: ctx.report,
    });
  }

  // ── 3. The sandbox. R6 lives entirely on the other side of this call. ────
  const rendered = await renderTemplate({
    id: `dev${deviceId}:rev${revision.id}`,
    entry: bundle.entry,
    sources: bundle.sources,
    context: ctx.context,
    options: revision.render_options as Record<string, boolean> | undefined,
  });

  if (!rendered.ok || rendered.output === null) {
    return await finish({
      status: 'error',
      errorKind: rendered.errorKind,
      errorMessage: rendered.errorMessage,
      variableReport: ctx.report,
    });
  }

  const body = rendered.output;

  // ── 4. §8.2, belt and braces ─────────────────────────────────────────────
  //
  // The context was redacted, so a secret cannot have arrived through a
  // variable. It CAN have arrived through the template text itself — an author
  // typing the PSK into the body — and that path no context redaction reaches.
  // Reading the plaintexts here is the one place this file touches them, they
  // are never returned, never logged and never stored.
  const secrets = await variableResolver.loadSecrets(tenantId, deviceId, {
    groupId: device.group_id,
    executor: q,
  });
  try {
    assertNoPlaintextSecret(body, secrets, 'this render');
  } catch (err) {
    return await finish({
      status: 'error',
      errorKind: 'template',
      errorMessage: err instanceof Error ? err.message : String(err),
      variableReport: ctx.report,
    });
  }

  // ── 5. Text -> NCM. The useful output. ───────────────────────────────────
  const claims = claimedKindsOf(body, revision.section_severity);
  if (claims.kinds.size === 0) {
    warnings.push(
      'This revision writes no section the NCM models. The desired document is empty and ' +
        'the plan it produces will contain no operation.',
    );
  }

  let ncmDesired: NcmDocument;
  try {
    const [rules, defaults] = await Promise.all([
      loadNormalizationRules(deviceId, tenantId, device.family),
      loadDefaults(device.family, device.os_version),
    ]);
    const normalizeCtx: NormalizeContextInput = {
      deviceId,
      tenantId,
      family: (device.family ?? 'mikrotik_routeros7') as DeviceFamily,
      // The device's version, NOT a version read from the render: a template
      // carries no `#` preamble, and `default_fill` is indexed by EXACT
      // version (N09). Passing the device's own version is what makes the
      // desired and observed documents comparable at all — normalised by the
      // same ruleset and the same defaults dictionary.
      osVersion: device.os_version,
      rules,
      defaults,
      via: 'ssh',
      // §3.4 case 2: ordinals on the DESIRED side are paired against the
      // OBSERVED document, so that a rule whose predicate already exists on the
      // box keeps its ordinal instead of colliding and producing a spurious
      // missing+extra pair.
      previous: (await latestDocument(deviceId))?.doc ?? null,
    };
    const out: NormalizeOutput = normalize(body, normalizeCtx);
    warnings.push(...out.warnings);

    const restricted: NcmDocument = {
      ...out.ncm,
      coverage: restrictCoverage(out.ncm.coverage, claims.kinds),
    };
    // Re-validated because the coverage was rewritten: `NcmDocumentAuthored`
    // refuses a kind declared `unsupported` while carrying records, which is
    // exactly the mistake a wrong claim computation would make.
    ncmDesired = NcmDocumentAuthored.parse(restricted) as NcmDocument;
  } catch (err) {
    return await finish({
      status: 'error',
      errorKind: 'parse',
      errorMessage:
        `The rendered configuration could not be turned into an NCM document: ` +
        `${err instanceof Error ? err.message : String(err)}`,
      variableReport: ctx.report,
    });
  }

  return await finish({
    status: 'ok',
    body,
    ncmDesired,
    claims,
    variableReport: ctx.report,
  });

  // ── local closure: one exit point, one place that writes the row ─────────

  async function finish(part: {
    status: RenderStatus;
    body?: string;
    ncmDesired?: NcmDocument;
    claims?: ReturnType<typeof claimedKindsOf>;
    errorKind?: RenderResultRecord['errorKind'];
    errorMessage?: string | null;
    variableReport: VariableReport | null;
  }): Promise<RenderResultRecord> {
    const variables = ctx?.variables ?? {};
    const snapshot = snapshotOf(variables);
    const varSha = variablesSha(snapshot);
    const bodyText = part.body ?? null;
    const doc = part.ncmDesired ?? null;

    const record: RenderResultRecord = {
      status: part.status,
      renderId: null,
      deviceId,
      tenantId,
      templateId,
      revisionId: String(revision.id),
      revision: revision.revision,
      assignmentId,
      body: bodyText,
      bodySha256: bodyText === null ? null : sha256(bodyText),
      ncmDesired: doc,
      ncmHash: doc ? ncmHash(doc) : null,
      claimedKinds: part.claims ? [...part.claims.kinds].sort() : [],
      unclaimedSections: part.claims?.unclaimedSections ?? [],
      variables,
      variablesSnapshot: snapshot,
      variablesSha256: varSha,
      secretKeys: ctx?.secretKeys ?? [],
      depsFingerprint: bundle?.depsFingerprint ?? null,
      osVersion: device.os_version,
      durationMs: Date.now() - started,
      warnings,
      errorKind: part.errorKind ?? null,
      errorMessage: part.errorMessage ?? null,
      variableReport: part.variableReport,
    };

    if (resolution && record.status === 'ok' && resolution.rejected.length > 0) {
      record.warnings.push(
        `${resolution.rejected.length} other assignment(s) were outranked or rejected for this device.`,
      );
    }

    if (opts.persist) record.renderId = await persistRender(q, record, opts.createdBy ?? null);
    return record;
  }
}

/** An override is injected as an `extra` context key, exactly like a device
 *  fact: `buildRenderContext` then refuses it if it collides with a resolved
 *  variable, which is the right answer — an override that silently shadowed a
 *  real value would make the preview lie about what a real render does. */
function overridesAsExtra(
  overrides: { key: string; value: JsonValue }[] | undefined,
): Record<string, JsonValue> {
  const out: Record<string, JsonValue> = {};
  for (const o of overrides ?? []) out[o.key] = o.value;
  return out;
}

/** The inspection report for an error path where `buildRenderContext` threw
 *  before producing one. Non-throwing by construction. */
async function safeReport(
  tenantId: number,
  deviceId: number,
  revision: RevisionRecord,
  device: DeviceRow,
  q: Knex | Knex.Transaction,
): Promise<VariableReport | null> {
  try {
    return await variableResolver.resolveForDevice(
      tenantId, deviceId, (revision.var_schema ?? null) as VarSchema | null,
      { groupId: device.group_id, executor: q },
    );
  } catch {
    return null;
  }
}

// ============================================================================
// Persistence
// ============================================================================

/**
 * Write ONE `config_renders` row.
 *
 * The last guard of §8.2 sits here, on the way in, not somewhere upstream: a
 * body still carrying a secret PLACEHOLDER is fine (that is the redacted form,
 * and it is what we want stored), but the row is refused if anything tries to
 * write a plaintext. The placeholder count is logged, because a placeholder
 * that survives into the artefact PUSHED to a device is an M6 bug and the
 * counter is what will make it visible.
 */
async function persistRender(
  q: Knex | Knex.Transaction,
  record: RenderResultRecord,
  createdBy: number | null,
): Promise<string> {
  const placeholders = record.body ? (record.body.match(SECRET_PLACEHOLDER_RE) ?? []).length : 0;
  if (placeholders > 0) {
    logger.debug(
      { deviceId: record.deviceId, revisionId: record.revisionId, placeholders },
      'render stored with redacted secret placeholders (§8.2)',
    );
  }

  const [row] = await q('config_renders')
    .insert({
      tenant_id: record.tenantId,
      device_id: record.deviceId,
      revision_id: record.revisionId,
      assignment_id: record.assignmentId,
      status: record.status,
      body: record.body,
      body_sha256: record.bodySha256,
      ncm_desired: record.ncmDesired ? JSON.stringify(record.ncmDesired) : null,
      ncm_hash: record.ncmHash,
      variables_snapshot: JSON.stringify(record.variablesSnapshot),
      variables_sha256: record.variablesSha256,
      deps_fingerprint: record.depsFingerprint,
      render_error: record.errorMessage,
      error_kind: record.errorKind,
      duration_ms: record.durationMs,
      os_version: record.osVersion,
      created_by: createdBy,
    })
    .returning('id');
  return String((row as { id: string | number }).id);
}

// ============================================================================
// Scratch preview — the TEMPLATE_WRITE surface
// ============================================================================

/**
 * Render an ARBITRARY BODY against a witness device.
 *
 * Kept as a separate function from `renderRevisionForDevice` for the reason
 * `loader.ts` keeps `loadScratchBundle` separate from `loadRevisionBundle`:
 * "render this string" is the same privilege as "author a template" (R6's
 * mitigation list names `TEMPLATE_WRITE` explicitly), and the difference has to
 * stay visible at the call site rather than living in a boolean.
 *
 * NEVER persists. A scratch body is not a revision, has no provenance, and a
 * `config_renders` row pointing at nothing is a drift verdict nobody can audit.
 */
export interface ScratchRenderResult {
  ok: boolean;
  body: string | null;
  ncmDesired: NcmDocument | null;
  ncmHash: string | null;
  claimedKinds: NcmResourceKind[];
  unclaimedSections: string[];
  variables: ResolvedVariables;
  variableReport: VariableReport | null;
  durationMs: number;
  warnings: string[];
  errorKind: RenderResultRecord['errorKind'];
  errorMessage: string | null;
}

export async function renderScratchForDevice(
  tenantId: number,
  deviceId: number,
  body: string,
  opts: {
    varSchema?: VarSchema | null;
    sectionSeverity?: unknown;
    renderOptions?: Record<string, boolean>;
    overrides?: { key: string; value: JsonValue }[];
    trx?: Knex | Knex.Transaction;
  } = {},
): Promise<ScratchRenderResult> {
  const q = opts.trx ?? db;
  const started = Date.now();
  const warnings: string[] = [];

  const device = await loadDevice(tenantId, deviceId, q);
  if (!RENDERABLE_BRANDS.has(device.brand)) {
    throw new RenderRefusedError(
      `Device #${deviceId} is a ${device.brand}; M5 previews RouterOS templates only.`,
      'brand_unsupported',
    );
  }

  const fail = (
    kind: RenderResultRecord['errorKind'],
    message: string,
    report: VariableReport | null,
  ): ScratchRenderResult => ({
    ok: false, body: null, ncmDesired: null, ncmHash: null, claimedKinds: [],
    unclaimedSections: [], variables: report?.variables ?? {}, variableReport: report,
    durationMs: Date.now() - started, warnings, errorKind: kind, errorMessage: message,
  });

  let ctx: RenderContext;
  try {
    ctx = await variableResolver.buildRenderContext(tenantId, deviceId, opts.varSchema ?? null, {
      groupId: device.group_id,
      mode: 'redacted',
      extra: { ...deviceFacts(device), ...overridesAsExtra(opts.overrides) },
      executor: q,
    });
  } catch (err) {
    if (err instanceof VariableResolutionError) {
      return fail('variables', err.message, null);
    }
    throw err;
  }

  let bundle: TemplateBundle;
  try {
    bundle = await loadScratchBundle(tenantId, body, { trx: q });
  } catch (err) {
    return fail('template', err instanceof Error ? err.message : String(err), ctx.report);
  }

  const rendered = await renderTemplate({
    id: `scratch:dev${deviceId}`,
    entry: bundle.entry,
    sources: bundle.sources,
    context: ctx.context,
    options: opts.renderOptions,
  });
  if (!rendered.ok || rendered.output === null) {
    return fail(
      rendered.errorKind,
      rendered.errorMessage ?? 'the render failed without recording a reason',
      ctx.report,
    );
  }

  const secrets = await variableResolver.loadSecrets(tenantId, deviceId, {
    groupId: device.group_id,
    executor: q,
  });
  try {
    assertNoPlaintextSecret(rendered.output, secrets, 'this preview');
  } catch (err) {
    return fail('template', err instanceof Error ? err.message : String(err), ctx.report);
  }

  const claims = claimedKindsOf(rendered.output, opts.sectionSeverity);

  const normalize = bindNormalizer();
  if (!normalize) throw new NoParserError(device.brand);

  try {
    const [rules, defaults] = await Promise.all([
      loadNormalizationRules(deviceId, tenantId, device.family),
      loadDefaults(device.family, device.os_version),
    ]);
    const out = normalize(rendered.output, {
      deviceId, tenantId,
      family: (device.family ?? 'mikrotik_routeros7') as DeviceFamily,
      osVersion: device.os_version,
      rules, defaults, via: 'ssh',
      previous: (await latestDocument(deviceId))?.doc ?? null,
    });
    warnings.push(...out.warnings);
    const doc = NcmDocumentAuthored.parse({
      ...out.ncm,
      coverage: restrictCoverage(out.ncm.coverage, claims.kinds),
    }) as NcmDocument;

    return {
      ok: true,
      body: rendered.output,
      ncmDesired: doc,
      ncmHash: ncmHash(doc),
      claimedKinds: [...claims.kinds].sort(),
      unclaimedSections: claims.unclaimedSections,
      variables: ctx.variables,
      variableReport: ctx.report,
      durationMs: Date.now() - started,
      warnings,
      errorKind: null,
      errorMessage: null,
    };
  } catch (err) {
    return fail('parse', err instanceof Error ? err.message : String(err), ctx.report);
  }
}

// ============================================================================
// Reads
// ============================================================================

export interface StoredRender {
  id: string;
  deviceId: number;
  revisionId: string;
  status: RenderStatus;
  bodySha256: string | null;
  ncmHash: string | null;
  renderedAt: Date;
}

/** The most recent successful render for a device, tenant-scoped. The planner
 *  uses it to avoid re-rendering when nothing moved. */
export async function latestRender(
  tenantId: number,
  deviceId: number,
  q: Knex | Knex.Transaction = db,
): Promise<StoredRender | null> {
  const row = (await q('config_renders')
    .where({ tenant_id: tenantId, device_id: deviceId, status: 'ok' })
    .orderBy('rendered_at', 'desc')
    .orderBy('id', 'desc')
    .first('id', 'device_id', 'revision_id', 'status', 'body_sha256', 'ncm_hash', 'rendered_at')) as
    | Record<string, unknown>
    | undefined;
  if (!row) return null;
  return {
    id: String(row.id),
    deviceId: Number(row.device_id),
    revisionId: String(row.revision_id),
    status: row.status as RenderStatus,
    bodySha256: (row.body_sha256 as string | null) ?? null,
    ncmHash: (row.ncm_hash as string | null) ?? null,
    renderedAt: row.rendered_at as Date,
  };
}

/** Full row, tenant-scoped, including `ncm_desired`. */
export async function getRender(
  tenantId: number,
  renderId: string | number,
  q: Knex | Knex.Transaction = db,
): Promise<(StoredRender & { body: string | null; ncmDesired: NcmDocument | null }) | null> {
  const row = (await q('config_renders')
    .where({ id: renderId, tenant_id: tenantId })
    .first('*')) as Record<string, unknown> | undefined;
  if (!row) return null;
  return {
    id: String(row.id),
    deviceId: Number(row.device_id),
    revisionId: String(row.revision_id),
    status: row.status as RenderStatus,
    bodySha256: (row.body_sha256 as string | null) ?? null,
    ncmHash: (row.ncm_hash as string | null) ?? null,
    renderedAt: row.rendered_at as Date,
    body: (row.body as string | null) ?? null,
    ncmDesired: (row.ncm_desired as NcmDocument | null) ?? null,
  };
}

export const renderService = {
  renderRevisionForDevice,
  renderScratchForDevice,
  latestRender,
  getRender,
  loadDevice,
  claimedKindsOf,
  restrictCoverage,
  snapshotOf,
  registerRenderNormalizer,
};
