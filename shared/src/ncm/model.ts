// ============================================================================
// @obliwan/shared — the NCM document
// ============================================================================
//
// Implements §2.4 of `docs/M4-NCM-contrat.md` (the study calls this file
// `document.ts`; ARCHITECTURE.md's source tree calls it `model.ts` — the tree
// wins, the content is the study's).
//
// This document is CONFIGURATION and nothing else. Operational state
// (counters, operStatus, uptime, dynamic leases, ARP, conntrack, active IPsec
// SAs, learned routes, PPP sessions) lives in `telemetry.ts` and must never
// appear here: if it did, `ncm_hash` would change on every collection, the
// `UNIQUE(device_id, ncm_hash)` deduplication would become a row generator, and
// the drift screen would report a change every five minutes (§1.2, §7.1).

import { z } from 'zod';
import { DEVICE_BRANDS, DEVICE_FAMILIES, TRANSPORT_KINDS } from '../device';
import {
  NCM_RESOURCE_KINDS, NcmResourceKind,
  NcmInterface, NcmVlan, NcmRoute, NcmFirewallRule, NcmNatRule,
  NcmDhcpScope, NcmIpsecPeer, NcmLocalUser, NcmService, NcmQosRule, NcmDhcpClient,
} from './resources';

/** Bumped on ANY change to the shape. Integer, monotone, never reused. */
export const NCM_VERSION = 2;

/** Bumped ONLY when the semKey algorithm changes. Embedded in every key as a
 *  prefix (`fw.v1:…`), because a bump invalidates every stored `sem_key`, every
 *  `drift_findings.sem_key` and every user-authored ignore rule (§8.4). */
export const SEM_KEY_GENERATION = 1;

/**
 * Coverage is the load-bearing field of this document.
 *
 *  'complete'    — the collector listed the whole resource set. ONLY this value
 *                  authorises the diff engine to emit `missing` / `extra`.
 *  'partial'     — some records were read, completeness not guaranteed (paged
 *                  API cut short, section-level timeout).
 *  'unsupported' — the family genuinely has no such concept, or this NCM
 *                  version predates the resource (§8.2).
 *  'failed'      — the collection was attempted and errored. Distinct from
 *                  'unsupported' the same way `error` is distinct from
 *                  `unreachable` in drift_runs.
 */
export const COVERAGE_STATES = ['complete', 'partial', 'unsupported', 'failed'] as const;
export type CoverageState = (typeof COVERAGE_STATES)[number];

export const NcmCoverage = z.object({
  state: z.enum(COVERAGE_STATES),
  via: z.enum(TRANSPORT_KINDS).nullable(),
  /** Required when state !== 'complete'. Shown verbatim in the UI. */
  reason: z.string().max(240).nullable(),
  /** EXCLUDED from ncmHash (§8.5): a record count that moved without any record
   *  changing would be a contradiction, and a record count that moved with them
   *  is already covered by the resources themselves. */
  recordCount: z.number().int().min(0),
}).strict();
export type NcmCoverage = z.infer<typeof NcmCoverage>;

/**
 * DIVERGENCE FROM THE STUDY, DELIBERATE.
 *
 * §2.4 writes `coverage: z.record(z.enum(NCM_RESOURCE_KINDS), NcmCoverage)`.
 * Measured on zod 3.25.76: a `z.record` with an enum key infers the FULL
 * `Record<NcmResourceKind, NcmCoverage>` at the type level but does NOT check
 * exhaustiveness at runtime — `{}` parses clean. Every consumer would then
 * write `doc.coverage.firewallRule.state` with no undefined guard, and a parser
 * that forgot one key would produce a TypeError inside the diff engine instead
 * of a fail-closed verdict. Since N3 ("no `missing` without
 * `coverage: 'complete'`") is THE guard that stops a partial collection from
 * generating a plan that recreates an entire firewall, its input may not be
 * unsound.
 *
 * The wire format is byte-identical to what the study specified — an object
 * keyed by resource kind. Only the schema is exhaustive.
 */
export const NcmCoverageMap = z.object({
  interface: NcmCoverage,
  vlan: NcmCoverage,
  route: NcmCoverage,
  firewallRule: NcmCoverage,
  natRule: NcmCoverage,
  dhcpScope: NcmCoverage,
  ipsecPeer: NcmCoverage,
  localUser: NcmCoverage,
  service: NcmCoverage,
  qosRule: NcmCoverage,
  /** v2. Optional so a stored v1 coverage map still validates; `coverageOf()`
   *  turns its absence into 'unsupported', which is the closed default and the
   *  right answer for every snapshot taken before the parser existed. */
  dhcpClient: NcmCoverage.optional(),
}).strict();
export type NcmCoverageMap = z.infer<typeof NcmCoverageMap>;

/** Belt and braces for the read path, where a hand-written or rolled-back row
 *  may be missing a key entirely. NEVER returns undefined, and the default is
 *  the closed one. */
export function coverageOf(
  coverage: Partial<NcmCoverageMap> | undefined,
  kind: NcmResourceKind,
): NcmCoverage {
  return (
    coverage?.[kind] ?? {
      state: 'unsupported',
      via: null,
      reason: 'coverage absent from document',
      recordCount: 0,
    }
  );
}

/**
 * N3, in one function. The diff engine calls this before emitting a single
 * `missing`, and there is no other legitimate way to make that decision.
 */
export function mayEmitMissing(
  coverage: Partial<NcmCoverageMap> | undefined,
  kind: NcmResourceKind,
): boolean {
  return coverageOf(coverage, kind).state === 'complete';
}

/** Convenience for parsers: everything unsupported, nothing claimed. Start
 *  here and upgrade the kinds you actually listed. */
export function emptyCoverage(reason: string): NcmCoverageMap {
  const out = {} as Record<NcmResourceKind, NcmCoverage>;
  for (const k of NCM_RESOURCE_KINDS) {
    out[k] = { state: 'unsupported', via: null, reason, recordCount: 0 };
  }
  return out as NcmCoverageMap;
}

/**
 * The honest boundary (§7). Every configuration section the parser SAW and did
 * not model lands here, with a count. This is what turns "the NCM is
 * incomplete" from a footnote into a measurable, prioritisable number — and
 * what lets K2 fail closed instead of approving a plan while blind.
 */
export const NcmUnmodeled = z.object({
  /** Brand-native section path: '/routing/ospf', 'Device.WiFi.', 'app-control'. */
  section: z.string().max(160),
  lineCount: z.number().int().min(0),
  /** true when the section can influence packet forwarding — K2 MUST degrade
   *  its verdict to INDETERMINATE when any such section is present (§6.4). */
  forwardingRelevant: z.boolean(),
}).strict();
export type NcmUnmodeled = z.infer<typeof NcmUnmodeled>;

export const NcmDeviceRef = z.object({
  deviceId: z.number().int().positive(),
  brand: z.enum(DEVICE_BRANDS),
  family: z.enum(DEVICE_FAMILIES),
  model: z.string().max(64).nullable(),
  /** Identity triple of D5 — carried INSIDE the document so a snapshot can be
   *  re-verified against the device it claims to describe after any import,
   *  export or restore. */
  serial: z.string().max(64).nullable(),
  systemIdentity: z.string().max(64).nullable(),
  pppUsername: z.string().max(64).nullable(),
  /** EXCLUDED from ncmHash (§8.5): a firmware upgrade must not, on its own,
   *  create a snapshot or a finding. It is already tracked in
   *  `devices.os_version` and `config_snapshots.os_version`. */
  osVersion: z.string().max(32).nullable(),
}).strict();
export type NcmDeviceRef = z.infer<typeof NcmDeviceRef>;

/** How far the O(n^2) order analysis of §4.3 got. `partial` means the chain
 *  exceeded 500 rules and only a ±25 window was compared: the drift UI shows
 *  the order analysis as degraded and K2 refuses to return ACCEPT. */
export const ORDER_ANALYSIS_STATES = ['full', 'partial', 'skipped'] as const;
export type OrderAnalysisState = (typeof ORDER_ANALYSIS_STATES)[number];

export const NcmResources = z.object({
  interfaces: z.array(NcmInterface),
  vlans: z.array(NcmVlan),
  routes: z.array(NcmRoute),
  firewallRules: z.array(NcmFirewallRule),   // ORDERED
  natRules: z.array(NcmNatRule),             // ORDERED
  dhcpScopes: z.array(NcmDhcpScope),
  ipsecPeers: z.array(NcmIpsecPeer),
  localUsers: z.array(NcmLocalUser),
  services: z.array(NcmService),
  qosRules: z.array(NcmQosRule),             // ORDERED
  /** v2. Defaulted so a stored v1 document still parses: it had no such key,
   *  and an absent collection is an empty one, never a validation failure. */
  dhcpClients: z.array(NcmDhcpClient).default([]),
}).strict();
export type NcmResources = z.infer<typeof NcmResources>;

export const NcmDocument = z.object({
  ncmVersion: z.number().int().positive(),
  semKeyGeneration: z.number().int().positive(),
  /**
   * Hash of the effective `normalization_rules` set applied to this document.
   * A change here explains an ncm_hash change that no human caused — the drift
   * run is then labelled `renormalization` and NEVER attributed to a person
   * (§6.5). It is INSIDE the hash on purpose: editing a normalization rule
   * really does change the NCM, so it really is a new snapshot.
   */
  normalizationEpoch: z.string().length(16),
  /** EXCLUDED from ncmHash — otherwise every collection is a new snapshot. */
  capturedAt: z.string().datetime(),
  device: NcmDeviceRef,
  coverage: NcmCoverageMap,
  /** How far the order analysis got, per §4.3. Documented here rather than on
   *  the drift run because it is a property of what we managed to COLLECT. */
  orderAnalysis: z.enum(ORDER_ANALYSIS_STATES),
  resources: NcmResources,
  unmodeled: z.array(NcmUnmodeled),
  /**
   * Escape hatch for brand data we want to keep but do not yet model.
   * EXCLUDED from ncmHash and from the diff by default: it must never be able
   * to create a finding, otherwise it becomes an unversioned second model.
   * Promoting a key out of `extensions` into a resource is an ncmVersion bump.
   *
   * Risk N-R9: this is one of the two doors through which a secret could still
   * reach the snapshot store. The entropy scanner of the CI golden-file test
   * exists precisely because of this field.
   */
  extensions: z.record(z.string().max(64), z.unknown()),
}).strict();
export type NcmDocument = z.infer<typeof NcmDocument>;

/**
 * Permissive reader for rows written by a NEWER server (rollback scenario).
 * Unknown keys are PRESERVED, never stripped — silently dropping a field on a
 * read-modify-write is how a snapshot store loses data.
 *
 * Note the asymmetry, and it is the point: resources are `.strict()` on WRITE,
 * so a parser that invents a field fails in test immediately; the document is
 * `passthrough` on READ, so a rollback does not destroy data.
 */
export const NcmDocumentStored = NcmDocument.passthrough();
export type NcmDocumentStored = z.infer<typeof NcmDocumentStored>;

/**
 * Extra write-time checks that cannot live on `NcmDocument` itself, because
 * `.superRefine` returns a ZodEffects and `NcmDocumentStored` needs
 * `.passthrough()`, which only a ZodObject has. Parsers validate against THIS;
 * readers validate against `NcmDocumentStored`.
 */
export const NcmDocumentAuthored = NcmDocument.superRefine((doc, ctx) => {
  // A non-complete coverage without a reason is an unexplained blind spot, and
  // §2.4 says the reason is shown verbatim in the UI.
  for (const kind of NCM_RESOURCE_KINDS) {
    // v2 kinds are optional in the map: an absent entry is not a missing reason,
    // it is a snapshot taken before that kind existed. Nothing to validate.
    const c = doc.coverage[kind];
    if (!c) continue;
    if (c.state !== 'complete' && (c.reason === null || c.reason.trim() === '')) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['coverage', kind, 'reason'],
        message: `coverage.${kind}.state is '${c.state}' and requires a reason`,
      });
    }
  }
  // A record that exists while the kind is declared 'unsupported' is a parser
  // bug that would otherwise silently disable N3 for that kind.
  const pairs: [NcmResourceKind, number][] = [
    ['interface', doc.resources.interfaces.length],
    ['vlan', doc.resources.vlans.length],
    ['route', doc.resources.routes.length],
    ['firewallRule', doc.resources.firewallRules.length],
    ['natRule', doc.resources.natRules.length],
    ['dhcpScope', doc.resources.dhcpScopes.length],
    ['ipsecPeer', doc.resources.ipsecPeers.length],
    ['localUser', doc.resources.localUsers.length],
    ['service', doc.resources.services.length],
    ['qosRule', doc.resources.qosRules.length],
  ];
  for (const [kind, count] of pairs) {
    if (count > 0 && doc.coverage[kind]?.state === 'unsupported') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['coverage', kind, 'state'],
        message: `${count} ${kind} record(s) present but coverage is 'unsupported'`,
      });
    }
  }
});
