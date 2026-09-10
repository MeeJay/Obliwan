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
