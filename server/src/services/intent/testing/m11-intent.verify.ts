// ============================================================================
// ObliWAN — M11 Intent Compiler self-test (K4)
// ============================================================================
//
// Pure functions and files. NOTHING here opens a socket, and that is itself one
// of the properties under test: the capability refusal has to happen before any
// network access, so a refused compilation must be reachable with a compile
// target that carries no transport, no credential and no host at all.
//
// Run:  npx tsx src/services/intent/testing/m11-intent.verify.ts

import { readFileSync, writeFileSync } from 'fs';
import type { DeviceFamily, NcmResource } from '@obliwan/shared';
import { NCM_RESOURCE_KINDS, buildSemKey } from '@obliwan/shared';
import type { SiteIntentDocument } from '@obliwan/shared/dist/intent';
import {
  SiteIntentDocument as SiteIntentSchema,
  describeGap,
  featuresRequiredBy,
} from '@obliwan/shared/dist/intent';
import { allBrandProfiles, brandProfile, renderableFamilies } from '../brandProfiles';
import { IntentCapabilityError, brandCoverage, capabilityCheck } from '../capabilityCheck';
import {
  assertArtefactRedacted,
  compileIntent,
  crossCheckArtifact,
  type IntentCompilation,
} from '../compiler.service';
import { rosQuote, token, vigorText, zldText } from '../renderers';
import { checkGoldenFiles, goldenPath, orphanGoldenFiles } from './goldenFiles';
import {
  GOLDEN_TARGET,
  deadManIntent,
  referenceSiteIntent,
  zoneAndCommitIntent,
} from './fixtures';

// ── harness ─────────────────────────────────────────────────────────────────

let passed = 0;
const failures: string[] = [];

function check(name: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    passed += 1;
    return;
  }
  failures.push(`${name}${detail === undefined ? '' : ` — ${JSON.stringify(detail)}`}`);
}

function eq<T>(name: string, actual: T, expected: T): void {
  check(name, Object.is(actual, expected), { actual, expected });
}

/** The four brands of the fleet, one family each. */
const FOUR_BRANDS: DeviceFamily[] = [
  'mikrotik_routeros7',
  'draytek_vigor',
  'zyxel_standalone',
  'sonicwall_sonicos',
];

function allResources(compilation: IntentCompilation): NcmResource[] {
  const r = compilation.document.resources;
  return [
    ...r.interfaces,
    ...r.vlans,
    ...r.routes,
    ...r.firewallRules,
    ...r.natRules,
    ...r.dhcpScopes,
    ...r.ipsecPeers,
    ...r.localUsers,
    ...r.services,
    ...r.qosRules,
  ];
}

// ── 1. one intent, four brands ──────────────────────────────────────────────

function oneIntentFourBrands(): void {
  const intent = referenceSiteIntent();
  const compilations = new Map<DeviceFamily, IntentCompilation>();

  for (const family of FOUR_BRANDS) {
    let compilation: IntentCompilation | null = null;
    try {
      compilation = compileIntent(intent, { ...GOLDEN_TARGET, family });
    } catch (err) {
      failures.push(`${family} refused a site every brand must handle — ${(err as Error).message}`);
      continue;
    }
    compilations.set(family, compilation);
    passed += 1;

    eq(`${family} brand`, compilation.brand, brandProfile(family).brand);
    eq(`${family} artefact format`, compilation.artifact.format, brandProfile(family).artifactFormat);
    check(`${family} artefact is not empty`, compilation.artifact.body.length > 500);
    check(`${family} ncm hash is a sha256`, /^[0-9a-f]{64}$/.test(compilation.ncmHash));

    // The indexer's consistency check: a stored semKey that disagrees with
    // `buildSemKey` is a parser — here a compiler — bug.
    const wrong = allResources(compilation).filter((r) => buildSemKey(r) !== r.semKey);
    eq(`${family}: every semKey re-derives`, wrong.length, 0);

    // Every record the compiler wrote is anchored, so drift on it can only ever
    // be a `changed` and never a `missing` + an `extra`.
    const unanchored = allResources(compilation).filter((r) => r.managedBy !== 'obliwan' || !r.managedSlug);
    eq(`${family}: every record carries the obliwan marker`, unanchored.length, 0);
  }

  eq('all four brands compiled', compilations.size, 4);
  if (compilations.size !== 4) return;

  // The point of K4: the same SITE, expressed four ways. The POLICY is
  // identical — same rules, same scopes, same tunnels, same markers — while the
  // names, the dialect and therefore the hash all differ.
  //
  // Interfaces and VLANs are deliberately NOT in this comparison: on Zyxel and
  // SonicWall the untagged segment IS the first LAN port, so the port has no
  // record of its own, while on MikroTik it is a bridge port that does. That is
  // a real difference in what the boxes are, not a difference in what the site
  // was asked to be, and flattening it would mean inventing a MikroTik bridge
  // port on a SonicWall.
  const policyMarkers = (c: IntentCompilation): string =>
    [
      ...c.document.resources.firewallRules,
      ...c.document.resources.natRules,
      ...c.document.resources.routes,
      ...c.document.resources.dhcpScopes,
      ...c.document.resources.ipsecPeers,
      ...c.document.resources.localUsers,
      ...c.document.resources.services,
      ...c.document.resources.qosRules,
    ]
      .map((r) => r.managedSlug)
      .sort()
      .join('|');

  const markerSets = FOUR_BRANDS.map((family) => policyMarkers(compilations.get(family) as IntentCompilation));
  check('the four brands produce the same policy, record for record', new Set(markerSets).size === 1, {
    distinct: new Set(markerSets).size,
  });

  const ruleCounts = FOUR_BRANDS.map(
    (f) => (compilations.get(f) as IntentCompilation).document.resources.firewallRules.length,
  );
  check('and the same number of firewall rules', new Set(ruleCounts).size === 1, ruleCounts);

  // Every brand still carries the whole site: two uplinks and two segments,
  // under whatever names that brand uses.
  for (const family of FOUR_BRANDS) {
    const site = compilations.get(family) as IntentCompilation;
    const addressed = site.document.resources.interfaces.filter((i) => i.addresses.length > 0);
    eq(`${family}: three addressed interfaces (static WAN + two segments)`, addressed.length, 3);
  }

  const hashes = FOUR_BRANDS.map((f) => (compilations.get(f) as IntentCompilation).ncmHash);
  eq('and four different documents, because the names differ', new Set(hashes).size, 4);

  const bodies = FOUR_BRANDS.map((f) => (compilations.get(f) as IntentCompilation).artifact.body);
  eq('and four different artefacts', new Set(bodies).size, 4);

  // Determinism: the same input twice is the same output twice, or no golden
  // file means anything.
  const twice = compileIntent(intent, { ...GOLDEN_TARGET, family: 'mikrotik_routeros7' });
  eq(
    'compiling twice is byte-identical',
    twice.artifact.sha256,
    (compilations.get('mikrotik_routeros7') as IntentCompilation).artifact.sha256,
  );
  eq(
    'and hash-identical',
    twice.ncmHash,
    (compilations.get('mikrotik_routeros7') as IntentCompilation).ncmHash,
  );

  // Brand-specific naming actually happened.
  const mt = compilations.get('mikrotik_routeros7') as IntentCompilation;
  const sw = compilations.get('sonicwall_sonicos') as IntentCompilation;
  check('MikroTik names its uplink ether1', mt.artifact.body.includes('ether1'));
  check('MikroTik builds a bridge', mt.artifact.body.includes('/interface bridge add name=bridge-lan'));
  check('SonicWall names its LAN X0', sw.artifact.body.includes('"X0"'));
  check('SonicWall uses zones, MikroTik does not', sw.artifact.body.includes('"LAN"') && !mt.artifact.body.includes('zone'));

  // §8.2 — the placeholders are there and nothing else is.
  for (const family of FOUR_BRANDS) {
    const body = (compilations.get(family) as IntentCompilation).artifact.body;
    check(`${family}: the PPPoE password is a vault placeholder`, body.includes('<<secret:lyon-nord-pppoe>>'));
    check(`${family}: the IPsec PSK is a vault placeholder`, body.includes('<<secret:lyon-nord-hq-psk>>'));
    check(`${family}: the admin password is a vault placeholder`, body.includes('<<secret:lyon-nord-admin>>'));
  }

  // The warnings an operator must read, and which do NOT block a compilation.
  const warnings = (compilations.get('mikrotik_routeros7') as IntentCompilation).warnings;
  eq('a site with restricted management and a restricted publication warns about nothing', warnings.length, 0);
}

// ── 2. the refusal, before any network access ───────────────────────────────

function capabilityRefusals(): void {
  const intent = zoneAndCommitIntent();

  // The refusal is reachable with a target that has no host, no credential and
  // no transport: there is nothing here that COULD dial anything.
  const expectations: Array<[DeviceFamily, string[]]> = [
    ['mikrotik_routeros7', ['policy.zoneModel', 'safety.atomicCommit']],
    ['draytek_vigor', ['policy.zoneModel', 'mgmt.snmpV3', 'safety.atomicCommit', 'safety.noRebootApply']],
    ['zyxel_standalone', ['safety.atomicCommit']],
  ];

  for (const [family, features] of expectations) {
    let error: IntentCapabilityError | null = null;
    try {
      compileIntent(intent, { ...GOLDEN_TARGET, family });
    } catch (err) {
      error = err instanceof IntentCapabilityError ? err : null;
      if (!error) failures.push(`${family} threw the wrong error type: ${(err as Error).name}`);
    }
    if (!error) {
      failures.push(`${family} compiled an intent it cannot satisfy`);
      continue;
    }
    passed += 1;

    const brand = brandProfile(family).brand;
    for (const feature of features) {
      const gap = error.gaps.find((g) => g.feature === feature);
      check(`${family} refuses ${feature}`, gap !== undefined, error.gaps.map((g) => g.feature));
      if (!gap) continue;
      eq(`${family}/${feature} names the brand`, gap.brand, brand);
      check(`${family}/${feature} message names the capability`, describeGap(gap).includes(feature));
      check(`${family}/${feature} message names the brand`, describeGap(gap).includes(brand));
      check(`${family}/${feature} points at the intent`, gap.intentPath.length > 0);
    }
    check(
      `${family}: the thrown message names every gap`,
      features.every((f) => error!.message.includes(f)),
      error.message,
    );
  }

  // And the one brand that CAN.
  let sonicwall: IntentCompilation | null = null;
  try {
    sonicwall = compileIntent(intent, { ...GOLDEN_TARGET, family: 'sonicwall_sonicos' });
  } catch (err) {
    failures.push(`SonicWall refused an intent it can satisfy — ${(err as Error).message}`);
  }
  check('only the SonicWall can promise an atomic commit', sonicwall !== null);
  if (sonicwall) {
    check(
      'and the zone policy really reached the artefact',
      sonicwall.artifact.body.includes('lyon-sud.fwd-z0'),
    );
  }

  // A family with no renderer refuses everything, including the baseline.
  for (const family of ['zyxel_nebula', 'zyxel_cpe'] as DeviceFamily[]) {
    const verdict = capabilityCheck(referenceSiteIntent(), family);
    check(`${family} is refused (no renderer)`, !verdict.ok);
    check(
      `${family} refuses the stateful firewall itself`,
      verdict.gaps.some((g) => g.feature === 'policy.statefulFirewall' && g.reason === 'family_cannot_express'),
    );
  }
}

// ── 3. our gap vs the hardware's gap ────────────────────────────────────────

function driverFlagRefusal(): void {
  const verdict = capabilityCheck(deadManIntent(), 'mikrotik_routeros7');
  check('an on-device dead-man is refused today', !verdict.ok);
  const gap = verdict.gaps.find((g) => g.feature === 'safety.onDeviceDeadMan');
  check('and the gap is reported', gap !== undefined);
  if (!gap) return;

  // The distinction the whole two-source design exists to express: RouterOS CAN
  // schedule a startup script, so blaming the router would be wrong; OUR driver
  // has not declared it, so the message names the flag.
  eq('the refusal blames the driver, not the router', gap.reason, 'driver_capability_missing');
  eq('and names the DeviceCapabilities flag', gap.capabilityFlag, 'canScheduleOnDevice');
  check(
    'the family profile does claim the feature',
    brandProfile('mikrotik_routeros7').support['safety.onDeviceDeadMan'],
  );
  check('the message names the flag', describeGap(gap).includes('canScheduleOnDevice'));

  // An observed override is the documented way a probe can grant it.
  const withOverride = capabilityCheck(deadManIntent(), 'mikrotik_routeros7', {
    canScheduleOnDevice: true,
  });
  check('a probed override lifts the refusal', withOverride.ok, withOverride.gaps.map(describeGap));
}

// ── 4. coverage — the plan that must not delete a firewall ──────────────────

function coverageIsOptIn(): void {
  const compilation = compileIntent(referenceSiteIntent(), {
    ...GOLDEN_TARGET,
    family: 'mikrotik_routeros7',
  });
  const complete = NCM_RESOURCE_KINDS.filter(
    (k) => compilation.document.coverage[k]?.state === 'complete',
  );
  eq('by default the intent claims NOTHING exhaustively', complete.length, 0);
  eq(
    'the kinds it wrote are partial, with a reason',
    compilation.document.coverage.firewallRule.state,
    'partial',
  );
  check(
    'and the reason is readable',
    (compilation.document.coverage.firewallRule.reason ?? '').length > 10,
  );
  eq(
    'a kind it never mentions is unsupported',
    compilation.document.coverage.qosRule.state === 'unsupported' ||
      compilation.document.coverage.qosRule.state === 'partial',
    true,
  );

  const authoritative = { ...referenceSiteIntent(), authoritative: ['firewallRule' as const] };
  const claimed = compileIntent(authoritative, { ...GOLDEN_TARGET, family: 'mikrotik_routeros7' });
  eq(
    'claiming a kind is an explicit gesture that shows up in the coverage',
    claimed.document.coverage.firewallRule.state,
    'complete',
  );
  eq(
    'and it changes the document identity',
    claimed.ncmHash === compilation.ncmHash,
    false,
  );
}

// ── 5. the two guards ───────────────────────────────────────────────────────

function guards(): void {
  const compilation = compileIntent(referenceSiteIntent(), {
    ...GOLDEN_TARGET,
    family: 'mikrotik_routeros7',
  });

  // Redaction: a tampered artefact is refused.
  let threw = false;
  try {
    assertArtefactRedacted(
      'routeros_script',
      compilation.artifact.body.replace('<<secret:lyon-nord-pppoe>>', 'hunter2-in-the-clear'),
    );
  } catch {
    threw = true;
  }
  check('a plaintext password in an artefact is refused (§8.2)', threw);

  let ok = true;
  try {
    assertArtefactRedacted('routeros_script', compilation.artifact.body);
  } catch {
    ok = false;
  }
  check('a correctly redacted artefact passes', ok);

  // Cross-check: an artefact that lost a record is refused.
  let diverged = false;
  try {
    crossCheckArtifact(
      compilation.document,
      compilation.artifact.body.split('\n').filter((l) => !l.includes('vlan30-guest')).join('\n'),
    );
  } catch {
    diverged = true;
  }
  check('an artefact missing an NCM record is refused', diverged);
}

// ── 5b. configuration injection through a free-text field ───────────────────
//
// THE FINDING THIS SECTION EXISTS FOR.
//
// `LanSegment.name`, `PortForward.comment`, `DhcpIntent.domain`,
// `LocalUserIntent.username` and their neighbours are free text written by
// whoever holds TEMPLATE_WRITE. Every one of them is interpolated into a line
// of RouterOS script, Vigor CLI or ZLD CLI. Before the fix, a segment named
//
//     x"⏎/user add name=bd group=full⏎#
//
// (33 characters, accepted by `z.string().min(1).max(64)`) rendered SIXTEEN
// standalone `/user add name=bd group=full` lines into the RouterOS artefact,
// nine into the Vigor one and ten into the ZLD one. `assertArtefactRedacted`
// saw no credential assignment; `crossCheckArtifact` saw every record present
// and had no opinion on lines in excess. The reviewer approved a LAN rename;
// the router got an unauthenticated `full` administrator reachable from the
// customer's LAN.
//
// Three barriers are asserted here, independently, because each of them has to
// hold on its own:
//   (a) the schema refuses the character at the API door;
//   (b) the renderers escape, on a document that BYPASSED the schema — which
//       is what an intent row stored before the regex looks like;
//   (c) `crossCheckArtifact` counts the lines and refuses an artefact with one
//       more than the renderer emitted, whatever produced it.

const INJECTED_COMMAND = '/user add name=bd group=full';
const INJECTION = `x"\n${INJECTED_COMMAND}\n#`;

function injectionThroughFreeText(): void {
  const base = referenceSiteIntent();

  // (a) the door.
  const doorFields: [string, unknown][] = [
    ['lans[0].name', { ...base, lans: [{ ...base.lans[0], name: INJECTION }, base.lans[1]] }],
    ['name', { ...base, name: INJECTION }],
    [
      'policy.publish[0].comment',
      { ...base, policy: { ...base.policy, publish: [{ ...base.policy.publish[0], comment: INJECTION }] } },
    ],
    [
      'lans[0].dhcp.domain',
      { ...base, lans: [{ ...base.lans[0], dhcp: { ...base.lans[0].dhcp!, domain: INJECTION } }, base.lans[1]] },
    ],
    [
      'lans[0].dhcp.reservations[0].hostname',
      {
        ...base,
        lans: [
          {
            ...base.lans[0],
            dhcp: {
              ...base.lans[0].dhcp!,
              reservations: [{ ...base.lans[0].dhcp!.reservations[0], hostname: INJECTION }],
            },
          },
          base.lans[1],
        ],
      },
    ],
    [
      'management.localUsers[0].username',
      {
        ...base,
        management: {
          ...base.management,
          localUsers: [{ ...base.management.localUsers[0], username: INJECTION }],
        },
      },
    ],
    [
      'management.snmp.username',
      { ...base, management: { ...base.management, snmp: { ...base.management.snmp!, username: INJECTION } } },
    ],
    ['vpn[0].remote', { ...base, vpn: [{ ...base.vpn[0], remote: INJECTION }] }],
    ['wan[0].pppoeUsername', { ...base, wan: [{ ...base.wan[0], pppoeUsername: INJECTION }, base.wan[1]] }],
  ];
  for (const [field, document] of doorFields) {
    const parsed = SiteIntentSchema.safeParse(document);
    check(`the schema refuses a line break in ${field}`, !parsed.success);
  }
  // …and still accepts the accented, punctuated names a French MSP really uses.
  check(
    'a site name with an accent and a dash is still accepted',
    SiteIntentSchema.safeParse({ ...base, name: 'Lyon Nord — étage 2 (siège)' }).success,
  );

  // (b) the renderers, on a document the schema never saw.
  const stored = {
    ...base,
    lans: [{ ...base.lans[0], name: INJECTION }, base.lans[1]],
  } as SiteIntentDocument;

  for (const family of renderableFamilies()) {
    const compilation = compileIntent(stored, { ...GOLDEN_TARGET, family });
    const lines = compilation.artifact.body.split('\n');
    eq(
      `${family}: no standalone command line was injected`,
      lines.filter((l) => l.trim() === INJECTED_COMMAND).length,
      0,
    );
    check(
      `${family}: the payload survives only as flattened text`,
      compilation.artifact.body.includes('/user add name=bd group=full') ||
        family === 'sonicwall_sonicos',
    );
  }

  // The RouterOS artefact is the one the finding measured. It has to be one
  // line, still commented, with the quote that would have closed it gone.
  const ros = compileIntent(stored, { ...GOLDEN_TARGET, family: 'mikrotik_routeros7' });
  const lanLine = ros.artifact.body
    .split('\n')
    .find((l) => l.startsWith('/interface bridge add') && l.includes('lan-s0'));
  check('the segment still renders on exactly one line', lanLine !== undefined);
  check('and that line carries no double quote from the intent', (lanLine ?? '').split('"').length === 3, lanLine);
  check(
    'and RouterOS command substitution characters are gone from it',
    !/[$;[\]]/.test((lanLine ?? '').slice((lanLine ?? '').indexOf('comment='))),
    lanLine,
  );

  // The escapers, stated as the properties the call sites rely on. Written as
  // a table over the characters rather than one example each: the first cut
  // of `rosQuote` lost the backslash — the escape character of all three
  // CLIs — to a shell heredoc, and a single hand-picked example would not
  // have noticed.
  const HOSTILE = ['\r', '\n', '"', '\\', '`'];
  const ROS_ALSO = ['$', ';', '[', ']', '{', '}'];
  for (const ch of HOSTILE) {
    const shown = JSON.stringify(ch);
    check(`rosQuote removes ${shown}`, !rosQuote(`a${ch}b`).includes(ch), rosQuote(`a${ch}b`));
    check(`vigorText removes ${shown}`, !vigorText(`a${ch}b`).includes(ch), vigorText(`a${ch}b`));
    check(`zldText removes ${shown}`, !zldText(`a${ch}b`).includes(ch), zldText(`a${ch}b`));
    check(`token removes ${shown}`, !token(`a${ch}b`).includes(ch), token(`a${ch}b`));
  }
  for (const ch of ROS_ALSO) {
    check(
      `rosQuote removes ${ch}, which RouterOS expands inside its own double quotes`,
      !rosQuote(`a${ch}b`).includes(ch),
      rosQuote(`a${ch}b`),
    );
  }
  check('token refuses a space', token('a b') === 'a_b');
  check('token keeps a real domain intact', token('lyon-nord.example') === 'lyon-nord.example');
  check(
    'rosQuote leaves an accented site name readable',
    rosQuote('Lyon Nord — étage 2') === 'Lyon Nord — étage 2',
    rosQuote('Lyon Nord — étage 2'),
  );

  // A backslash payload: on a CLI it escapes the quote that was supposed to
  // contain the value, so it opens the same door a newline does.
  const escaped = {
    ...base,
    lans: [{ ...base.lans[0], name: 'x\\" ; /user add name=bd2 group=full' }, base.lans[1]],
  } as SiteIntentDocument;
  for (const family of renderableFamilies()) {
    const body = compileIntent(escaped, { ...GOLDEN_TARGET, family }).artifact.body;
    check(
      `${family}: a backslash from an intent field never reaches the artefact`,
      family === 'sonicwall_sonicos' || !body.includes('\\'),
      body.split('\n').find((l) => l.includes('\\')),
    );
  }

  // (c) the counting guard, independent of who escaped what: an artefact with
  //     one line more than the renderer emitted is refused even though every
  //     NCM record is still in it.
  const clean = compileIntent(referenceSiteIntent(), { ...GOLDEN_TARGET, family: 'mikrotik_routeros7' });
  const emitted = clean.artifact.body.split('\n').length;
  let refusedExtra = false;
  try {
    crossCheckArtifact(clean.document, `${clean.artifact.body}\n${INJECTED_COMMAND}`, emitted);
  } catch {
    refusedExtra = true;
  }
  check('an artefact with a line the renderer did not emit is refused', refusedExtra);

  let acceptedExact = true;
  try {
    crossCheckArtifact(clean.document, clean.artifact.body, emitted);
  } catch {
    acceptedExact = false;
  }
  check('and the untouched artefact still passes the same guard', acceptedExact);

  let refusedCr = false;
  try {
    crossCheckArtifact(clean.document, clean.artifact.body.replace('\n', '\r\n'), null);
  } catch {
    refusedCr = true;
  }
  check('a carriage return in an artefact is refused', refusedCr);
}

// ── 6. golden files ─────────────────────────────────────────────────────────

function goldenFiles(): void {
  const mismatches = checkGoldenFiles();
  eq('every golden file matches', mismatches.length, 0);
  for (const m of mismatches) {
    failures.push(`golden ${m.family}: ${m.reason} at line ${m.line}\n    expected: ${m.expected}\n    actual:   ${m.actual}`);
  }
  eq('no orphan golden file', orphanGoldenFiles().length, 0);
  eq('one golden file per renderable family', renderableFamilies().length, 5);

  // THE property the golden files exist for: one modified line breaks the run.
  // Proved by modifying one, checking, and putting it back.
  const family: DeviceFamily = 'draytek_vigor';
  const path = goldenPath(family);
  const original = readFileSync(path, 'utf8');
  try {
    const lines = original.split('\n');
    const target = lines.findIndex((l) => l.startsWith('ip lan '));
    check('the golden file has a line to perturb', target >= 0);
    lines[target] = lines[target].replace('10.20.0.1', '10.20.0.2');
    writeFileSync(path, lines.join('\n'), 'utf8');

    const broken = checkGoldenFiles();
    const hit = broken.find((m) => m.family === family);
    check('a one-character change breaks the golden test', hit !== undefined);
    eq('and it reports the right line', hit?.line, target + 1);
    eq('and no other family is disturbed', broken.length, 1);
  } finally {
    writeFileSync(path, original, 'utf8');
  }
  eq('the golden file was restored', checkGoldenFiles().length, 0);
}

// ── 7. the brand coverage panel (risk R2) ───────────────────────────────────

function coverageMatrix(): void {
  const rows = brandCoverage();
  eq('every family has a row', rows.length, allBrandProfiles().length);
  for (const row of rows) {
    if (row.artifactFormat === null) {
      check(`${row.family} declares no feature it cannot render`, Object.values(row.support).every((v) => v === false));
      check(`${row.family} says why`, row.notes.length > 0);
    } else {
      check(`${row.family} supports the stateful firewall`, row.support['policy.statefulFirewall']);
    }
  }
  const sonicwall = rows.find((r) => r.family === 'sonicwall_sonicos');
  check('the panel shows SonicWall as the brand that commits atomically', sonicwall?.capabilities.requiresExplicitCommit === true);
  const draytek = rows.find((r) => r.family === 'draytek_vigor');
  check('and DrayTek as the brand that reboots to apply', draytek?.capabilities.requiresRebootToApply === true);

  // The requirement list is a pure function of the intent, callable with no
  // device in sight — this is what the client uses to grey out brands.
  const required = featuresRequiredBy(referenceSiteIntent());
  check('the reference site needs a firewall', required.some((u) => u.feature === 'policy.statefulFirewall'));
  check('and VLAN segmentation', required.some((u) => u.feature === 'lan.vlanSegmentation'));
  check('and does NOT need a zone model', !required.some((u) => u.feature === 'policy.zoneModel'));
}

// ── run ─────────────────────────────────────────────────────────────────────

oneIntentFourBrands();
capabilityRefusals();
driverFlagRefusal();
coverageIsOptIn();
guards();
injectionThroughFreeText();
goldenFiles();
coverageMatrix();

process.stdout.write(`\nM11 intent compiler — ${passed} assertion(s) passed, ${failures.length} failed\n`);
for (const failure of failures) process.stdout.write(`  FAIL ${failure}\n`);
process.exitCode = failures.length === 0 ? 0 : 1;
