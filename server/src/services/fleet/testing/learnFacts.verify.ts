/**
 * ObliWAN — the rule `learnDeviceFacts` must never relax.
 *
 * Filling a blank and changing a known value look like the same line of code
 * and are opposite acts. An empty column means "nobody has told us"; a filled
 * one is the claim `assertTargetBinding()` checks before every write (D5 / R4).
 *
 * The failure this guards against is subtle and total: if a probe were allowed
 * to overwrite a stored serial, then swapping the box at a given address would
 * make ObliWAN quietly rewrite its own records to match whatever answered —
 * and the binding check would pass forever afterwards, against the wrong
 * hardware. The guard would still be there, still running, and permanently
 * blind. So the merge rule is tested on its own, as a pure function.
 *
 *   npx tsx src/services/fleet/testing/learnFacts.verify.ts
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

const LEARNABLE = ['model', 'serial', 'os_version', 'system_identity'] as const;

/** The merge, lifted verbatim from `learnDeviceFacts`. */
function merge(
  current: Record<string, string | null>,
  observed: Record<string, string | null>,
): {
  patch: Record<string, string>;
  conflicts: Array<{ field: string; stored: string; observed: string }>;
} {
  const patch: Record<string, string> = {};
  const conflicts: Array<{ field: string; stored: string; observed: string }> = [];
  for (const field of LEARNABLE) {
    const seen = observed[field]?.trim();
    if (!seen) continue;
    const stored = current[field]?.trim();
    if (!stored) patch[field] = seen;
    else if (stored !== seen) conflicts.push({ field, stored, observed: seen });
  }
  return { patch, conflicts };
}

function main(): void {
  console.log('\nlearnDeviceFacts — filling blanks\n');

  const blank = merge(
    { model: null, serial: null, os_version: null, system_identity: null },
    { model: 'RB4011iGS+', serial: '968A099D1F3C', os_version: '7.14.3', system_identity: 'Mik-Central' },
  );
  check('every empty column is filled from the probe', Object.keys(blank.patch).length === 4);
  check('the model arrives', blank.patch.model === 'RB4011iGS+');
  check('the serial arrives', blank.patch.serial === '968A099D1F3C');
  check('nothing is reported as a conflict', blank.conflicts.length === 0);

  const partial = merge(
    { model: 'RB4011', serial: null, os_version: null, system_identity: 'Mik-Central' },
    { model: 'RB4011', serial: '968A099D1F3C', os_version: '7.14.3', system_identity: 'Mik-Central' },
  );
  check(
    'a column that already agrees is not rewritten (no pointless UPDATE)',
    partial.patch.model === undefined && partial.patch.system_identity === undefined,
  );
  check('the still-empty columns are filled', Object.keys(partial.patch).length === 2);

  console.log('\nlearnDeviceFacts — refusing to overwrite (D5 / R4)\n');

  const swapped = merge(
    { model: 'RB4011', serial: '968A099D1F3C', os_version: '7.14.3', system_identity: 'Mik-Central' },
    { model: 'RB5009', serial: 'AAAABBBBCCCC', os_version: '7.15', system_identity: 'Not-Yours' },
  );
  check(
    'a DIFFERENT serial is never written',
    swapped.patch.serial === undefined,
    `patch was ${JSON.stringify(swapped.patch)}`,
  );
  check('a different serial is reported as a conflict', swapped.conflicts.some((c) => c.field === 'serial'));
  check('a different system identity is reported as a conflict',
    swapped.conflicts.some((c) => c.field === 'system_identity'));
  check(
    'a box that answers with a wholly different identity produces NO writes at all',
    Object.keys(swapped.patch).length === 0,
  );
  check('…and four conflicts', swapped.conflicts.length === 4);

  console.log('\nlearnDeviceFacts — silence is not an answer\n');

  const silent = merge(
    { model: 'RB4011', serial: '968A099D1F3C', os_version: null, system_identity: null },
    { model: null, serial: null, os_version: null, system_identity: null },
  );
  check('a probe that reports nothing writes nothing', Object.keys(silent.patch).length === 0);
  check('…and invents no conflict', silent.conflicts.length === 0);

  const blankish = merge(
    { model: null, serial: null, os_version: null, system_identity: null },
    { model: '   ', serial: '', os_version: null, system_identity: 'Mik-Central' },
  );
  check(
    'whitespace and empty strings are not facts',
    blankish.patch.model === undefined && blankish.patch.serial === undefined,
  );
  check('a real value alongside them still lands', blankish.patch.system_identity === 'Mik-Central');

  // A CHR is a virtual machine: it legitimately has no RouterBOARD serial.
  // That must fill nothing and accuse nobody.
  const chr = merge(
    { model: null, serial: null, os_version: null, system_identity: 'CHR-Paris' },
    { model: null, serial: null, os_version: '7.14.3', system_identity: 'CHR-Paris' },
  );
  check(
    'a CHR with no serial fills only what it did report',
    Object.keys(chr.patch).length === 1 && chr.patch.os_version === '7.14.3',
  );
  check('…and raises no conflict over the serial it does not have', chr.conflicts.length === 0);

  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exit(failed === 0 ? 0 : 1);
}

main();
