/**
 * ObliWAN — acceptance for `applyOverSsh()`, the write path of three brands.
 *
 * Run: npx tsx src/services/change/testing/m6-sshapply.verify.ts
 *
 * No database, no fleet, no network beyond loopback. A real ssh2 server on an
 * ephemeral port, a real interactive channel, and the function under test
 * driving it exactly as it would drive a Vigor.
 *
 * WHAT IS BEING PROVEN, AND WHY EACH ONE MATTERS
 *
 *  1. `applied` equals what the DEVICE received. Everything §8.3 does after a
 *     failed push — how much to roll back, whether the change is partial — is
 *     computed from this number. A function that over-reports it does not fail
 *     loudly; it produces a rollback that restores too little.
 *  2. A refusal stops the loop AT the refused line. The next lines must never
 *     reach the device: a firewall half-written in the wrong order is worse
 *     than one not written.
 *  3. `failedAt` is the INDEX of the refused command, and it is the index the
 *     operator will read next to the line they typed.
 *  4. Answers split across two TCP writes change nothing. A prompt matcher
 *     that assumes one chunk per command passes on loopback and fails on a DSL
 *     line — the failure nobody reproduces.
 *  5. A device that wedges mid-apply times out and reports what it DID apply,
 *     rather than zero or everything.
 *  6. A connection dropped mid-apply is not silently a success.
 *  7. Secrets never appear in what the caller is handed for the audit trail.
 */

import { applyOverSsh, SSH_DIALECTS } from '../safeApply.service';
import { startFakeSshRouter, throwawaySecret, type FakeSshRouter } from './fakeSshRouter';

let passed = 0;
let failed = 0;

function check(label: string, ok: boolean, detail?: unknown): void {
  if (ok) { passed++; console.log(`  ok   ${label}`); }
  else { failed++; console.log(`  FAIL ${label}${detail === undefined ? '' : ` — ${JSON.stringify(detail)}`}`); }
}
function eq(label: string, actual: unknown, expected: unknown): void {
  check(label, Object.is(actual, expected), { actual, expected });
}

const ERROR_PATTERN = /% Invalid input|command failed|syntax error/i;

function options(router: FakeSshRouter, commands: string[], extra: Partial<Parameters<typeof applyOverSsh>[0]> = {}) {
  return {
    host: '127.0.0.1',
    port: router.port,
    username: 'obliwan-svc',
    password: throwawaySecret(),
    commands,
    redacted: commands.map((c) => c.replace(/(password=)\S+/g, '$1***')),
    secretValues: [],
    errorPattern: ERROR_PATTERN,
    timeoutMs: 8_000,
    ...extra,
  };
}

async function main(): Promise<void> {
  console.log('\n== 1. A clean apply: every line lands, and `applied` is the truth ==');
  {
    const router = await startFakeSshRouter();
    const cmds = ['set firewall rule 1 accept', 'set firewall rule 2 drop', 'commit'];
    const r = await applyOverSsh(options(router, cmds));
    eq('no error', r.error, null);
    eq('failedAt is null', r.failedAt, null);
    eq('applied counts every line', r.applied, cmds.length);
    eq('the device received exactly those lines', router.received.join('|'), cmds.join('|'));
    await router.close();
  }

  console.log('\n== 2. A refusal stops AT the line, and later lines never reach the box ==');
  {
    const router = await startFakeSshRouter({ refuse: /rule 2/, errorText: '% Invalid input detected' });
    const cmds = ['set firewall rule 1 accept', 'set firewall rule 2 drop', 'commit'];
    const r = await applyOverSsh(options(router, cmds));
    check('an error is reported', r.error !== null, r.error);
    eq('failedAt is the refused index', r.failedAt, 1);
    eq('applied counts only what succeeded', r.applied, 1);
    eq('the third line was NEVER sent', router.received.includes('commit'), false);
    await router.close();
  }

  console.log('\n== 3. Answers split across two TCP writes change nothing ==');
  {
    const router = await startFakeSshRouter({ splitWrites: true });
    const cmds = ['set a', 'set b', 'set c', 'commit'];
    const r = await applyOverSsh(options(router, cmds));
    eq('no error on a fragmented stream', r.error, null);
    eq('applied is still exact', r.applied, cmds.length);
    eq('the device saw each line once', router.received.length, cmds.length);
    await router.close();
  }

  console.log('\n== 4. A device that wedges mid-apply: timeout reports the PARTIAL truth ==');
  {
    const router = await startFakeSshRouter({ silentAfter: 2 });
    const cmds = ['set a', 'set b', 'set c', 'commit'];
    const r = await applyOverSsh(options(router, cmds, { timeoutMs: 1_500 }));
    check('an error is reported', r.error !== null, r.error);
    eq('applied is what the device answered, not what we sent', r.applied, 2);
    check('the box did receive the line it never answered', router.received.length >= 3, router.received);
    await router.close();
  }

  console.log('\n== 5. A connection dropped mid-apply is not a success ==');
  {
    const router = await startFakeSshRouter({ closeAfter: 2 });
    const cmds = ['set a', 'set b', 'set c', 'commit'];
    const r = await applyOverSsh(options(router, cmds, { timeoutMs: 3_000 }));
    check('applied never exceeds what was answered', r.applied <= 2, r.applied);
    check('the run did not claim the whole batch', r.applied < cmds.length, r.applied);
    await router.close();
  }

  console.log('\n== 6. The audit trail the caller receives carries no secret ==');
  {
    const router = await startFakeSshRouter();
    const secret = 'S3cr3t-PSK-value';
    const cmds = [`set ipsec peer 1 password=${secret}`, 'commit'];
    const seen: string[] = [];
    const r = await applyOverSsh(
      options(router, cmds, { secretValues: [secret], onLine: (l) => seen.push(l) }),
    );
    eq('the apply succeeded', r.error, null);
    check('the device DID get the real secret (§8.2: vault -> equipment)',
      router.received.some((l) => l.includes(secret)));
    check('nothing handed to the caller contains it', seen.every((l) => !l.includes(secret)), seen);
    await router.close();
  }

  // ── 7. Every dialect, against a device that speaks it ────────────────────
  //
  // The `errorPattern` of `SSH_DIALECTS` is the ENTIRE failure detector of the
  // write path: none of these boxes sets a usable exit code on a config line.
  // A pattern that is too narrow does not throw and does not log — the device
  // prints its refusal, nothing matches, the line is counted APPLIED, the job
  // goes green and §8.3 sees no reason to roll anything back.
  //
  // So each dialect is replayed against a fake that answers with ITS prompt and
  // ITS refusal phrase. What is proven is the PAIRING: that the phrase a device
  // of this family would print is one this table recognises. What is not
  // proven, and cannot be here, is that the phrase is the right one — that
  // needs a transcript off real hardware.
  console.log('\n== 7. Each dialect: its prompt is understood and its refusal is caught ==');
  const CASES: Array<{ family: keyof typeof SSH_DIALECTS; prompt: string; refusal: string }> = [
    { family: 'draytek_vigor', prompt: '\r\nDrayTek> ', refusal: '% Invalid input detected' },
    { family: 'zyxel_standalone', prompt: '\r\nRouter# ', refusal: 'ERROR: incomplete command' },
    { family: 'sonicwall_sonicos', prompt: '\r\nTZ370> ', refusal: '% Command not allowed' },
  ];

  for (const c of CASES) {
    const dialect = SSH_DIALECTS[c.family];

    // 7a — a clean batch: the prompt is recognised, nothing is lost.
    const clean = await startFakeSshRouter({ prompt: c.prompt });
    const cmds = ['set a', 'set b', dialect.commitVerb ?? 'set c'];
    const okRun = await applyOverSsh(
      options(clean, cmds, { errorPattern: dialect.errorPattern, promptPattern: dialect.promptPattern }),
    );
    eq(`${c.family}: clean batch applies fully`, okRun.applied, cmds.length);
    eq(`${c.family}: the device received every line`, clean.received.length, cmds.length);
    await clean.close();

    // 7b — the refusal this family prints IS matched by this family's pattern.
    check(`${c.family}: its refusal phrase matches its errorPattern`,
      dialect.errorPattern.test(c.refusal), c.refusal);

    const bad = await startFakeSshRouter({ prompt: c.prompt, refuse: /set b/, errorText: c.refusal });
    const badRun = await applyOverSsh(
      options(bad, ['set a', 'set b', 'set c'], {
        errorPattern: dialect.errorPattern,
        promptPattern: dialect.promptPattern,
      }),
    );
    eq(`${c.family}: the refusal stops the batch at its line`, badRun.failedAt, 1);
    eq(`${c.family}: nothing after the refusal was sent`, bad.received.includes('set c'), false);
    await bad.close();

    // 7c — a dialect that needs an explicit commit says so, in the table.
    if (dialect.commitVerb !== null) {
      check(`${c.family}: commitVerb "${dialect.commitVerb}" is recorded with its reason`,
        dialect.note.length > 20);
    }
  }

  console.log(`\n${passed} passed, ${failed} failed\n`);
  if (failed > 0) process.exitCode = 1;
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
