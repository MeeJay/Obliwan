// ============================================================================
// @obliwan/shared — canonical serialisation and ncmHash
// ============================================================================
//
// Implements §8.5 of `docs/M4-NCM-contrat.md`.
//
// `ncm_hash` is the deduplication key of `config_snapshots`
// (`UNIQUE(device_id, ncm_hash)`). If it is unstable, the snapshot table grows
// without a single real change and the drift screen reports a change on every
// collection — risk N-R3, and the failure mode no unit test sees. Everything in
// this file exists to make that hash a pure function of CONFIGURATION.

import { canonicalJson, sha256Hex } from './hash';
import { ORDERED_RESOURCE_KINDS, NcmResourceKind } from './resources';
import type { NcmDocument } from './model';

/**
 * The document keys, in the order the serializer walks them. Explicit rather
 * than `Object.keys().sort()` on purpose: `canonicalJson` already sorts, and an
 * explicit list makes the review of "what is hashed" a diff on ONE array.
 */
/**
 * `since` — THE NCM VERSION THAT INTRODUCED THIS COLLECTION.
 *
 * ┌─ WHY A NEW RESOURCE KIND CANNOT SIMPLY BE APPENDED ───────────────────────┐
 * │ `canonicalize()` serialises every collection listed here, empty ones      │
 * │ included, and `ncmHash()` hashes that string. Appending one line to this  │
 * │ array therefore adds `"newThing":[]` to the canonical form of EVERY       │
 * │ document ever stored — every `ncm_hash` in `config_snapshots` and every   │
 * │ `base_state_hash` on a frozen plan shifts at once. On the next drift run  │
 * │ the entire fleet reports as changed, which is risk R3 arriving in one     │
 * │ sweep and taking the product's credibility with it.                       │
 * │                                                                          │
 * │ So the hash is VERSIONED, not the schema alone. A collection is included  │
 * │ only when the document's own `ncmVersion` is at least its `since`. A      │
 * │ document stamped v1 hashes byte-for-byte as it did before this line was   │
 * │ written — which is the property that makes adding a kind a deployable     │
 * │ change instead of a fleet-wide false alarm.                               │
 * │                                                                          │
 * │ Corollary for whoever adds the next one: give it the NEXT version, bump   │
 * │ `NCM_VERSION`, and never retro-date a `since`. Retro-dating is exactly    │
 * │ the silent rehash this field exists to prevent.                           │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const HASHED_COLLECTIONS: readonly {
  key: keyof NcmDocument['resources'];
  kind: NcmResourceKind;
  since: number;
}[] = [
  { key: 'interfaces', kind: 'interface', since: 1 },
  { key: 'vlans', kind: 'vlan', since: 1 },
  { key: 'routes', kind: 'route', since: 1 },
  { key: 'firewallRules', kind: 'firewallRule', since: 1 },
  { key: 'natRules', kind: 'natRule', since: 1 },
  { key: 'dhcpScopes', kind: 'dhcpScope', since: 1 },
  { key: 'ipsecPeers', kind: 'ipsecPeer', since: 1 },
  { key: 'localUsers', kind: 'localUser', since: 1 },
  { key: 'services', kind: 'service', since: 1 },
  { key: 'qosRules', kind: 'qosRule', since: 1 },
  { key: 'dhcpClients', kind: 'dhcpClient', since: 2 },
];

type Keyed = { semKey?: unknown };

function bySemKey(a: Keyed, b: Keyed): number {
  const x = typeof a.semKey === 'string' ? a.semKey : '';
  const y = typeof b.semKey === 'string' ? b.semKey : '';
  return x < y ? -1 : x > y ? 1 : 0;
}

/**
 * Orders the ten resource collections.
 *
 *  - The three ORDERED kinds (firewall, nat, qos) keep COLLECTION ORDER. That
 *    is the whole reason `ORDERED_RESOURCE_KINDS` exists: sorting a firewall
 *    chain destroys its semantics, and a hash that ignored order would call two
 *    genuinely different firewalls identical.
 *  - Everything else is sorted by `semKey`, so a device that re-emits its
 *    interface list in a different order does not create a snapshot.
 *
 * Nested arrays are NOT touched. `dnsServers` is primary-then-secondary and
 * `taggedPorts` may be significant on some brands; sorting them here would be
 * the platform silently deciding that an ordering carries no meaning. Parsers
 * normalise what genuinely is a set (see `normalizeSelector`,
 * `normalizeTokenSet`), and they do it BEFORE the hash, which is where that
 * decision belongs.
 *
 * The one exception is `dhcpScope.reservations`: it carries `semKey`, it is a
 * set by construction (one entry per MAC), and RouterOS emits it in `.id`
 * order, which churns on every edit.
 */
function orderResources(
  resources: NcmDocument['resources'],
  ncmVersion: number,
): Record<string, unknown[]> {
  const out: Record<string, unknown[]> = {};
  for (const { key, kind, since } of HASHED_COLLECTIONS) {
    // A collection younger than the document is not part of that document's
    // canonical form. Not "empty" — ABSENT, exactly as it was on the day the
    // snapshot was taken. See the box on HASHED_COLLECTIONS.
    if (since > ncmVersion) continue;
    const arr = (resources[key] ?? []) as unknown as Keyed[];
    const copy = arr.slice();
    if (!ORDERED_RESOURCE_KINDS.has(kind)) copy.sort(bySemKey);
    out[key] = copy.map((r) => {
      const rec = r as Record<string, unknown>;
      if (kind === 'dhcpScope' && Array.isArray(rec.reservations)) {
        return { ...rec, reservations: (rec.reservations as Keyed[]).slice().sort(bySemKey) };
      }
      return rec;
    });
  }
  return out;
}

/**
 * Deterministic serialisation of a WHOLE document (nothing stripped). Exposed
 * because the property test of §8.5 asserts
 * `canonicalize(parse(canonicalize(d))) === canonicalize(d)` and because a
 * golden-file test is far more readable against this than against a hash.
 */
export function canonicalize(doc: NcmDocument): string {
  return canonicalJson({
    ncmVersion: doc.ncmVersion,
    semKeyGeneration: doc.semKeyGeneration,
    normalizationEpoch: doc.normalizationEpoch,
    capturedAt: doc.capturedAt,
    device: doc.device,
    coverage: doc.coverage,
    orderAnalysis: doc.orderAnalysis,
    resources: orderResources(doc.resources, doc.ncmVersion),
    unmodeled: doc.unmodeled.slice().sort((a, b) =>
      a.section < b.section ? -1 : a.section > b.section ? 1 : 0),
    extensions: doc.extensions,
  });
}

/**
 * The hashing scope, §8.5, and every line of it is a decision:
 *
 * STRIPPED — a change here must NOT create a snapshot:
 *   capturedAt              every collection would be a new snapshot
 *   device.osVersion        a firmware upgrade is not a config change; it is
 *                           already tracked in `devices.os_version` and
 *                           `config_snapshots.os_version`
 *   coverage[*].recordCount redundant with the resources themselves
 *   coverage[*].via         collection metadata; switching a device from SSH to
 *                           the API must not rewrite the whole fleet's hashes
 *   coverage[*].reason      free text about a failure ("timeout after 31s"),
 *                           which differs between two identical partial reads
 *   extensions              unversioned by definition; it must never be able to
 *                           create a finding, so it must not create a snapshot
 *
 * KEPT — a change here IS a different snapshot, on purpose:
 *   ncmVersion, semKeyGeneration, normalizationEpoch, coverage[*].state,
 *   orderAnalysis, unmodeled[], and every resource.
 *
 * `normalizationEpoch` being inside is deliberate: editing a normalization rule
 * really does change the NCM. The resulting drift run is labelled
 * `renormalization` and is NEVER attributed to a human (§6.5).
 *
 * NOTE on `coverage`: §8.5's "STRIPPED" list names only `recordCount`, but its
 * "KEPT" list names `coverage[*].state` specifically rather than `coverage`.
 * We follow the more specific of the two — state only — because `via` and
 * `reason` are collection metadata by exactly the same argument that strips
 * `recordCount`.
 */
export function stripForHash(doc: NcmDocument): Record<string, unknown> {
  const coverage: Record<string, unknown> = {};
  for (const k of Object.keys(doc.coverage) as (keyof NcmDocument['coverage'])[]) {
    const entry = doc.coverage[k];
    if (entry) coverage[k] = { state: entry.state };
  }
  const { osVersion: _osVersion, ...device } = doc.device;

  return {
    ncmVersion: doc.ncmVersion,
    semKeyGeneration: doc.semKeyGeneration,
    normalizationEpoch: doc.normalizationEpoch,
    device,
    coverage,
    orderAnalysis: doc.orderAnalysis,
    resources: orderResources(doc.resources, doc.ncmVersion),
    unmodeled: doc.unmodeled.slice().sort((a, b) =>
      a.section < b.section ? -1 : a.section > b.section ? 1 : 0),
  };
}

/** `ncmHash = sha256(canonicalize(strip(doc)))` — lowercase hex, 64 chars.
 *  This is the value stored in `config_snapshots.ncm_hash`. */
export function ncmHash(doc: NcmDocument): string {
  return sha256Hex(canonicalJson(stripForHash(doc)));
}
