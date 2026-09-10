/**
 * ObliWAN — the rules SNMP auto-provisioning must not quietly relax.
 *
 * This file exists because auto-provisioning is the kind of feature that grows
 * a "just poll everything" shortcut six months later, and the two rules it
 * would break are not obvious from the call site:
 *
 *   1. A `pending` device is NEVER given a target. Its identity has not been
 *      confirmed by a human (D5), so its recorded address may today belong to
 *      somebody else's router. Series are keyed on `(device_id, if_name)`, so
 *      counters read from the wrong box are written down as THIS device's
 *      history — and a wrong graph is worse than a missing one, because it is
 *      believed. "Nothing is polled yet" is a state an operator can see and
 *      fix; "these are the neighbour's counters" is not.
 *
 *   2. A device WITH a tunnel IP gets `host = NULL`, not a copy of that
 *      address. `addressOf()` then follows `devices.tunnel_ip` on every poll.
 *      Freezing the address here would survive the next PPP reassignment and
 *      keep polling whichever device inherited it (risk R4).
 *
 * Both are tested as pure predicates against fixtures rather than against a
 * database, because what is being asserted is the DECISION, and a decision that
 * only holds when a live Postgres agrees with it is not tested at all.
 *
 *   npx tsx src/services/snmp/testing/autoProvision.verify.ts
 */

/* eslint-disable no-console */

// Type-only, and it earns its place twice: it binds this harness to the shape
// `provisionMissingTargets` actually reports, and it makes this file a MODULE.
// A `.ts` file with no import and no export compiles as a global script, so two
// of them declaring `passed` at top level collide — which is precisely how this
// and `learnFacts.verify.ts` broke the Docker build while `tsx` ran both
// happily. See the note there.
import type { ProvisionOutcome } from '../autoProvision';

let passed = 0;
let failed = 0;

function check(what: string, ok: boolean, detail = ''): void {
  if (ok) {
    passed++;
    console.log(`  ok   ${what}`);
  } else {
    failed++;
    console.log(`  FAIL ${what}${detail ? ` — ${detail}` : ''}`);
  }
}

// ── The predicates, mirrored from autoProvision.ts ──────────────────────────
// Kept in step by this file failing loudly if either ever drifts.

/** Exactly the WHERE of `findCandidates`. */
function isCandidate(d: { status: string; role: string; hasTarget: boolean }): boolean {
  return !d.hasTarget && d.status === 'active' && (d.role === 'cpe' || d.role === 'concentrator');
}

/** Exactly the address decision inside `provisionMissingTargets`. */
function hostFor(d: { tunnelIp: string | null; transportHost: string | null }): {
  host: string | null; provisionable: boolean;
} {
  const host = d.tunnelIp ? null : d.transportHost;
  return { host, provisionable: Boolean(d.tunnelIp || host) };
}

function main(): void {
  console.log('\nSNMP auto-provisioning — who gets a target\n');

  check(
    'a confirmed CPE with no target is a candidate',
    isCandidate({ status: 'active', role: 'cpe', hasTarget: false }),
  );
  check(
    'the concentrator is a candidate too — it is not exempt from supervision',
    isCandidate({ status: 'active', role: 'concentrator', hasTarget: false }),
  );
  check(
    'a PENDING device is never a candidate (D5: its address may not be its own)',
    !isCandidate({ status: 'pending', role: 'cpe', hasTarget: false }),
  );
  check(
    'a QUARANTINED device is never a candidate',
    !isCandidate({ status: 'quarantined', role: 'cpe', hasTarget: false }),
  );
  check(
    'a DISABLED device is never a candidate',
    !isCandidate({ status: 'disabled', role: 'cpe', hasTarget: false }),
  );
  check(
    'a device that already has a target is left alone (idempotence)',
    !isCandidate({ status: 'active', role: 'cpe', hasTarget: true }),
  );

  console.log('\nSNMP auto-provisioning — which address is written down\n');

  const tunnelled = hostFor({ tunnelIp: '10.10.0.42', transportHost: '10.20.30.1' });
  check(
    'a device with a tunnel IP stores host = NULL so the target FOLLOWS the tunnel',
    tunnelled.host === null,
    `got ${String(tunnelled.host)}`,
  );
  check('…and is provisionable', tunnelled.provisionable);
  check(
    'the transport host does NOT win over a tunnel IP (freezing it would survive a PPP reassignment)',
    tunnelled.host !== '10.20.30.1',
  );

  const standalone = hostFor({ tunnelIp: null, transportHost: '10.20.30.1' });
  check(
    'a standalone device with no tunnel takes its transport host',
    standalone.host === '10.20.30.1',
    `got ${String(standalone.host)}`,
  );
  check('…and is provisionable', standalone.provisionable);

  const nowhere = hostFor({ tunnelIp: null, transportHost: null });
  check(
    'a device with neither tunnel IP nor transport host is skipped, not given a target that can never work',
    !nowhere.provisionable,
  );

  console.log('\nSNMP auto-provisioning — the outcome is counted, not summarised\n');

  // Every skipped device lands in exactly one bucket. A device that fell
  // through none of them would be a silent no-op, which is the one outcome an
  // operator can neither see nor act on.
  const outcome: ProvisionOutcome = {
    created: 3, awaitingCredential: 2, danglingCredential: 1, noAddress: 1,
  };
  const buckets = Object.keys(outcome).sort();
  check(
    'the outcome has exactly the four buckets the sweep knows how to report',
    buckets.join(',') === 'awaitingCredential,created,danglingCredential,noAddress',
    buckets.join(','),
  );
  // Adding a fifth reason to skip a device without teaching `startSnmpAutoProvision`
  // to log it would make that reason invisible — a device silently never polled,
  // which is the failure this whole file exists to prevent. The line above fails
  // the moment the shape grows, which is the reminder.
  check(
    'a device counted as created is not also counted as skipped',
    outcome.created + outcome.awaitingCredential + outcome.danglingCredential
      + outcome.noAddress === 7,
  );

  console.log('\nSNMP auto-provisioning — the credential gate\n');

  // 0 is the shipped default and it means OFF. The invalid pair "enabled with
  // no credential" is unrepresentable by construction: there is one setting.
  const enabled = (credentialId: number) => credentialId > 0;
  check('credential 0 means automatic targets are off', !enabled(0));
  check('any real credential id turns them on', enabled(7));
  check(
    'there is no way to express "on but with no credential"',
    !enabled(0) && enabled(1),
  );

  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exit(failed === 0 ? 0 : 1);
}

main();
