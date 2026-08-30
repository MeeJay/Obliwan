// ============================================================================
// ObliWAN — capabilityCheck: the refusal that happens before the network
// ============================================================================
//
// ┌─ THE ONE PROPERTY THIS FILE EXISTS FOR ───────────────────────────────────┐
// │ An intent that asks for something the hardware cannot do must fail AT     │
// │ COMPILATION, before a single socket is opened, before a credential is     │
// │ decrypted, before a change job is created. Not at apply time, not         │
// │ half-way through a push, and never as a device that quietly did not get   │
// │ its VLANs.                                                                │
// │                                                                           │
// │ Everything this module reads is declarative:                              │
// │   - `IntentSupport` from the brand profile (default NO_INTENT_SUPPORT);   │
// │   - `DeviceCapabilities` from the driver registry (default                │
// │     NO_CAPABILITIES), optionally layered with the per-unit                │
// │     `observed_overrides` measured at probe time.                          │
// │ No I/O of any kind happens here. That is checkable by reading the imports.│
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ WHY TWO SOURCES AND NOT ONE ─────────────────────────────────────────────┐
// │ They answer two different questions and they are allowed to disagree:     │
// │                                                                           │
// │   IntentSupport      "can this PRODUCT FAMILY express this at all?"       │
// │   DeviceCapabilities "does OUR DRIVER declare it can do this?"            │
// │                                                                           │
// │ RouterOS can schedule an on-box dead-man — the family says `true`. The    │
// │ MikroTik driver has not shipped `canScheduleOnDevice` yet — the driver    │
// │ says `false`. The honest verdict is a refusal that names                  │
// │ `canScheduleOnDevice`, so the reader knows it is OUR gap and not the      │
// │ router's. Averaging the two, or trusting only one, would have made that   │
// │ sentence impossible to write.                                             │
// └───────────────────────────────────────────────────────────────────────────┘

import type { DeviceCapabilities, DeviceCapabilityFlag, DeviceFamily, ObservedCapabilityOverrides } from '@obliwan/shared';
import type {
  BrandCoverageRow,
  CapabilityGap,
  CapabilityVerdict,
  IntentFeature,
  SiteIntentDocument,
} from '@obliwan/shared/dist/intent';
import {
  FEATURE_FORBIDS_FLAGS,
  FEATURE_REQUIRES_FLAGS,
  INTENT_FEATURE_LABELS,
  describeGap,
  featuresRequiredBy,
} from '@obliwan/shared/dist/intent';
import { getCapabilities } from '../drivers';
import { allBrandProfiles, brandProfile } from './brandProfiles';

/**
 * A compilation refused for capability reasons.
 *
 * Distinct from every other error the intent path can raise, because it is the
 * ONLY one that is not a bug and not an outage: it is the product answering a
 * question the technician would otherwise have had to ask a colleague. It is a
 * 422 on the API and a table on the screen, never a 500.
 */
export class IntentCapabilityError extends Error {
  readonly gaps: CapabilityGap[];
  readonly family: DeviceFamily;

  constructor(family: DeviceFamily, gaps: CapabilityGap[]) {
    super(
      `intent cannot be compiled for ${family}: ${gaps.length} unsupported ` +
        `capabilit${gaps.length === 1 ? 'y' : 'ies'}\n  - ${gaps.map(describeGap).join('\n  - ')}`,
    );
    this.name = 'IntentCapabilityError';
    this.family = family;
    this.gaps = gaps;
  }
}

/**
 * The family defaults, with the per-unit probe results layered on top.
 *
 * `observed_overrides` is how "this particular SonicWall has the REST API
 * switched off" reaches a decision. Only boolean flags can be overridden — a
 * probe can discover that a transport does not answer; it cannot discover a new
 * `applyGranularity`.
 */
export function effectiveCapabilities(
  family: DeviceFamily,
  overrides?: ObservedCapabilityOverrides | null,
): DeviceCapabilities {
  const base = getCapabilities(family);
  if (!overrides) return base;
  const out: DeviceCapabilities = { ...base };
  for (const key of Object.keys(overrides) as DeviceCapabilityFlag[]) {
    const value = overrides[key];
    if (typeof value === 'boolean') {
      (out as unknown as Record<string, unknown>)[key] = value;
    }
  }
  return out;
}

/**
 * Can this family satisfy this intent?
 *
 * Returns EVERY gap, never the first one. A technician who fixes one refusal
 * only to meet the next one on the following attempt learns to distrust the
 * tool; the whole list is what turns a refusal into a decision ("this site
 * needs a different box" or "drop the guest VLAN").
 */
export function capabilityCheck(
  intent: SiteIntentDocument,
  family: DeviceFamily,
  overrides?: ObservedCapabilityOverrides | null,
): CapabilityVerdict {
  const profile = brandProfile(family);
  const capabilities = effectiveCapabilities(family, overrides);
  const required = featuresRequiredBy(intent);
  const gaps: CapabilityGap[] = [];

  const gap = (
    feature: IntentFeature,
    intentPath: string,
    reason: CapabilityGap['reason'],
    capabilityFlag: DeviceCapabilityFlag | null,
  ): CapabilityGap => ({
    feature,
    featureLabel: INTENT_FEATURE_LABELS[feature],
    brand: profile.brand,
    family,
    reason,
    capabilityFlag,
    intentPath,
    note: profile.featureNotes[feature] ?? null,
  });

  for (const use of required) {
    // 1. Does the FAMILY have any way to express it?
    if (!profile.support[use.feature]) {
      gaps.push(gap(use.feature, use.path, 'family_cannot_express', null));
      // No second opinion is useful once the product cannot do it at all.
      continue;
    }

    // 2. Does OUR DRIVER declare the flags this feature rides on?
    for (const flag of FEATURE_REQUIRES_FLAGS[use.feature] ?? []) {
      if (capabilities[flag] !== true) {
        gaps.push(gap(use.feature, use.path, 'driver_capability_missing', flag));
      }
    }
    for (const flag of FEATURE_FORBIDS_FLAGS[use.feature] ?? []) {
      if (capabilities[flag] === true) {
        gaps.push(gap(use.feature, use.path, 'driver_capability_conflicts', flag));
      }
    }
  }

  return { brand: profile.brand, family, ok: gaps.length === 0, required, gaps };
}

/** The same verdict for a set of families — the "which of my boxes could take
 *  this site" screen, computed without touching one of them. */
export function capabilityCheckMany(
  intent: SiteIntentDocument,
  families: readonly DeviceFamily[],
): CapabilityVerdict[] {
  return families.map((f) => capabilityCheck(intent, f));
}

/**
 * The gate. Every compilation goes through it, and it is the reason
 * `compileIntent` can assume its brand profile is able to render what it is
 * handed.
 */
export function assertCapable(
  intent: SiteIntentDocument,
  family: DeviceFamily,
  overrides?: ObservedCapabilityOverrides | null,
): CapabilityVerdict {
  const verdict = capabilityCheck(intent, family, overrides);
  if (!verdict.ok) throw new IntentCapabilityError(family, verdict.gaps);
  return verdict;
}

/**
 * The whole matrix, for the UI panel risk R2 demands: the coverage per brand
 * has to be VISIBLE rather than implied, or the product re-creates the "TR-069
 * covers everything" expectation it exists to correct.
 */
export function brandCoverage(): BrandCoverageRow[] {
  return allBrandProfiles().map((profile) => {
    const c = getCapabilities(profile.family);
    return {
      brand: profile.brand,
      family: profile.family,
      artifactFormat: profile.artifactFormat,
      support: profile.support,
      capabilities: {
        configFormat: c.configFormat,
        applyGranularity: c.applyGranularity,
        supportsStructuredDiff: c.supportsStructuredDiff,
        requiresExplicitCommit: c.requiresExplicitCommit,
        requiresRebootToApply: c.requiresRebootToApply,
        canScheduleOnDevice: c.canScheduleOnDevice,
      },
      notes: profile.notes,
    };
  });
}
