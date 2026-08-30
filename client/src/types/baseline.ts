// ObliWAN client — Fleet takeover / Golden Site DTOs (M12, killer K8).
//
// ── THE PROBLEM K8 SOLVES ───────────────────────────────────────────────────
// §1.2/K8: "sans lui il faut écrire les templates à la main avant que l'outil
// ne serve à quoi que ce soit, et le projet meurt à la troisième semaine." The
// miner takes N existing configs, cuts them into atomic FACTS, finds which
// facts are shared, and proposes a template. The whole feature lives or dies on
// one number: **"present on 27 of 30"**.
//
// That fraction is the reason `FactCluster.presentOn` and `.total` are two
// separate fields and never a pre-computed percentage. "90 %" hides whether the
// denominator is 30 sites or 3, and a template drafted from three sites is a
// guess wearing a statistic. The screen prints "27 / 30" and the raw count of
// what is missing, always.
//
// ── THE SECOND NUMBER: WHAT IS *NOT* COVERED ────────────────────────────────
// §5/M12's acceptance test is "≥ 80 % des lignes couvertes par le template
// déduit, chaque écart listé et classable". So the draft carries
// `coveredFacts` AND `uncoveredFacts`, and the uncovered ones are enumerable.
// A takeover tool that reports only its successes leaves the operator to
// discover the other 20 % on the day a site breaks.
//
// ── "SPÉCIFICITÉ CLIENT" IS A DECISION, NOT A DISMISSAL ─────────────────────
// Marking a divergence as a client specificity turns it into a DOCUMENTED
// exception: it stops counting against the conformance score and it acquires a
// reason and an author. `FactException` therefore has a mandatory `reason` and
// records who wrote it. An "ignore" button with no reason field is how a fleet
// accumulates 400 unexplained exceptions in a year, at which point the
// conformance score means nothing at all.
//
// ── NO LLM ──────────────────────────────────────────────────────────────────
// §5/M12 is explicit: hierarchical clustering with a weighted Jaccard distance,
// in a worker, WITHOUT an LLM. Nothing in this file assumes a generative step,
// and `similarity` is a number the operator can reason about.

import type { DeviceBrand, DeviceFamily } from '@obliwan/shared';

// ── Mining runs ─────────────────────────────────────────────────────────────

export const BASELINE_RUN_STATES = ['queued', 'running', 'done', 'failed'] as const;
export type BaselineRunState = (typeof BASELINE_RUN_STATES)[number];

export interface BaselineRun {
  id: number;
  state: BaselineRunState;
  /** Devices whose latest snapshot went into the mine. */
  deviceCount: number;
  /** Devices EXCLUDED for want of a snapshot. Reported separately, never
   *  folded into `deviceCount`: a run over 12 of 30 boxes that presents itself
   *  as a run over 30 produces a "present on 12/12" template. */
  devicesWithoutSnapshot: number;
  clusterCount: number;
  startedAt: string;
  finishedAt: string | null;
  error: string | null;
  createdByName: string | null;
}

export interface StartRunRequest {
  /** Empty = every device the session can read that carries a snapshot. */
  deviceIds?: number[];
  brand?: DeviceBrand;
  /** Jaccard distance at which the hierarchical tree is cut. Exposed because
   *  the operator is the only one who knows whether his two "clusters" are
   *  really one customer with two eras of installer. */
  threshold?: number;
}

// ── Clusters ────────────────────────────────────────────────────────────────

export interface ClusterMember {
  deviceId: number;
  deviceName: string | null;
  siteName: string | null;
  brand: DeviceBrand | null;
  family: DeviceFamily | null;
  /** 0..1 similarity to the cluster's centroid. */
  similarity: number;
  /** Facts this member has that the cluster does not — its own divergences. */
  divergenceCount: number;
}

export interface DeducedVariable {
  /** Suggested template variable name, e.g. `site_lan_cidr`. */
  name: string;
  /** The fact field it was extracted from. */
  factPath: string;
  /** Distinct values observed, ALREADY REDACTED server-side. Rendered through
   *  `secretScan` anyway: an "extracted variable" over a PPP password field is
   *  exactly the shape of the last audit's finding (§8.2). */
  sampleValues: string[];
  distinctCount: number;
  /** Devices in which the variable was found at all. */
  presentOn: number;
}

export interface FactCluster {
  id: number;
  /** Miner-assigned label, e.g. `cluster-2`. Renamed by the operator later. */
  name: string;
  brand: DeviceBrand | null;
  family: DeviceFamily | null;
  members: ClusterMember[];
  /** Facts shared by every member — the skeleton of the future template. */
  commonFactCount: number;
  /** Facts held by SOME members. The interesting ones. */
  variableFactCount: number;
  variables: DeducedVariable[];
  /** Mean intra-cluster similarity, 0..1. */
  cohesion: number;
}

// ── Facts ───────────────────────────────────────────────────────────────────

export const FACT_CLASSES = [
  /** In the draft template, identical everywhere. */
  'common',
  /** In the draft, parameterised by a deduced variable. */
  'variable',
  /** NOT in the draft. A divergence somebody has to classify. */
  'outlier',
  /** An outlier that has been accepted as a documented client specificity. */
  'exception',
] as const;
export type FactClass = (typeof FACT_CLASSES)[number];

export interface BaselineFact {
  id: string;
  /** NCM resource the fact came from: `firewall.filter`, `ip.address`. */
  resource: string;
  /** Semantic key inside that resource. */
  semKey: string;
  /** One-line rendering of the fact. Redacted server-side; scanned here. */
  summary: string;
  klass: FactClass;
  /** THE NUMBER. Never pre-divided into a percentage. */
  presentOn: number;
  total: number;
  /** Devices that do NOT carry it, named. "3 sites differ" is a statistic;
   *  "Lyon-2, Nantes-1 and Brest-4 differ" is a work list. */
  missingFrom: Array<{ deviceId: number; deviceName: string | null }>;
  exception: FactException | null;
}

export interface FactException {
  reason: string;
  createdByName: string | null;
  createdAt: string;
}

// ── Template drafts ─────────────────────────────────────────────────────────

export interface TemplateDraft {
  clusterId: number;
  /** Nunjucks body. Never applied from this screen — it is proposed to
   *  `/templates`, and publishing stays behind TEMPLATE_WRITE there. */
  body: string;
  variables: DeducedVariable[];
  /** §5/M12's acceptance criterion, as two counts rather than a percentage. */
  coveredFacts: number;
  totalFacts: number;
  /** The facts the draft does NOT express, enumerated. */
  uncoveredFactIds: string[];
  generatedAt: string;
}

/** Coverage as a fraction, computed where it is displayed and nowhere else. */
export function draftCoverage(draft: TemplateDraft): number | null {
  if (draft.totalFacts <= 0) return null;
  return draft.coveredFacts / draft.totalFacts;
}

// ── Conformance ─────────────────────────────────────────────────────────────

/**
 * Per-device conformance to its cluster's draft.
 *
 * `documentedExceptions` is subtracted from the divergences before the score is
 * computed, which is the entire incentive for writing the reason down: an
 * exception that has been explained stops costing points, an unexplained one
 * does not. `score` is `null` when the device has no snapshot — never 0, which
 * would read as "totally non-conformant" for a box nobody has looked at.
 */
export interface ConformanceRow {
  deviceId: number;
  deviceName: string | null;
  siteName: string | null;
  clusterId: number | null;
  clusterName: string | null;
  score: number | null;
  matchedFacts: number;
  divergences: number;
  documentedExceptions: number;
  evaluatedAt: string | null;
}
