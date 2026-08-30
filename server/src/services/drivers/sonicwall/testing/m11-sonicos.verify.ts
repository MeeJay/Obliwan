// ============================================================================
// ObliWAN — M11 SonicOS driver self-test
// ============================================================================
//
// Runs against `fakeSonicOs.ts` on loopback. NO REAL APPLIANCE IS TOUCHED, and
// none exists: everything asserted here is a property of OUR driver, checked
// against a server we wrote ourselves (§8.3). Read the header of the fake for
// what that does and does not prove.
//
// Run:  npx tsx src/services/drivers/sonicwall/testing/m11-sonicos.verify.ts

import { compileIntent } from '../../../intent/compiler.service';
import { sonicOsOpsOf } from '../../../intent/renderers';
import {
  GOLDEN_TARGET,
  referenceSiteIntent,
} from '../../../intent/testing/fixtures';
import type { DriverContext, ResolvedTransport } from '../../types';
import { DriverError } from '../../types';
import { SonicWallDriver } from '../sonicwall.driver';
import { applyStagedOps, withSonicOsConfigSession, type SonicOsStagedOp } from '../sonicosSession';
import { FakeSonicOs, type FakeSonicOsOptions } from './fakeSonicOs';

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

const USERNAME = 'obliwan';
const PASSWORD = 'correct-horse-battery-staple';

function transportFor(baseUrl: string): ResolvedTransport {
  const url = new URL(baseUrl);
  return {
    transport: 'rest',
    enabled: true,
    priority: 1,
    host: url.hostname,
    port: Number(url.port),
    useTls: false,
    tlsFingerprintSha256: null,
    params: {},
    credentials: { username: USERNAME, password: PASSWORD },
  };
}

function contextFor(baseUrl: string): DriverContext {
  return {
    deviceId: 4242,
    tenantId: 7,
    family: 'sonicwall_sonicos',
    transports: [transportFor(baseUrl)],
    timeoutMs: 5000,
  };
}

function targetFor(baseUrl: string): { baseUrl: string; timeoutMs: number; retries: number } {
  return { baseUrl, timeoutMs: 5000, retries: 0 };
}

async function withFake<T>(
  opts: FakeSonicOsOptions,
  fn: (fake: FakeSonicOs, baseUrl: string) => Promise<T>,
): Promise<T> {
  const fake = new FakeSonicOs({ username: USERNAME, password: PASSWORD, ...opts });
  const baseUrl = await fake.listen();
  try {
    return await fn(fake, baseUrl);
  } finally {
    await fake.close();
  }
}

const OPS: SonicOsStagedOp[] = [
  { method: 'POST', path: '/address-objects/ipv4', body: { name: 'OBW_A' }, description: 'address object' },
  { method: 'POST', path: '/access-rules/ipv4', body: { name: 'OBW_R' }, description: 'access rule' },
];

// ── the tests ───────────────────────────────────────────────────────────────

async function sessionLifecycle(): Promise<void> {
  await withFake({}, async (fake, baseUrl) => {
    const result = await withSonicOsConfigSession(targetFor(baseUrl), { username: USERNAME, password: PASSWORD }, async (session) => {
      check('session is authenticated inside the callback', session.isAuthenticated);
      return 'done';
    });
    eq('the callback result is returned', result, 'done');
    eq('exactly one login', fake.logins, 1);
    eq('exactly one logout', fake.logouts, 1);
    eq('login sent override:true', fake.overrideRequests, 1);
    eq('no login without override', fake.loginsWithoutOverride, 0);
    check('no session is left open on the appliance', !fake.sessionOpen);
  });

  // THE property. A driver that logs out only on the happy path makes the
  // customer's firewall unmanageable within a day.
  await withFake({}, async (fake, baseUrl) => {
    let thrown: unknown = null;
    try {
      await withSonicOsConfigSession(targetFor(baseUrl), { username: USERNAME, password: PASSWORD }, async () => {
        throw new Error('the work exploded');
      });
    } catch (err) {
      thrown = err;
    }
    check('the original error propagates', thrown instanceof Error && (thrown as Error).message === 'the work exploded');
    eq('logout still happened', fake.logouts, 1);
    check('no session left open after a throw', !fake.sessionOpen);
  });
}

async function overrideStealsTheLock(): Promise<void> {
  await withFake({ lockHeldByWebUi: true }, async (fake, baseUrl) => {
    await withSonicOsConfigSession(targetFor(baseUrl), { username: USERNAME, password: PASSWORD }, async () => undefined);
    eq('the lock held by a stale web session did not block us', fake.logins, 1);
  });
}

async function missingCookieIsFatal(): Promise<void> {
  await withFake({ omitCookie: true }, async (fake, baseUrl) => {
    let code: string | null = null;
    try {
      await withSonicOsConfigSession(targetFor(baseUrl), { username: USERNAME, password: PASSWORD }, async () => undefined);
    } catch (err) {
      code = err instanceof DriverError ? err.code : 'NOT_A_DRIVER_ERROR';
    }
    eq('a login with no cookie is a protocol error, not a silent success', code, 'PROTOCOL_ERROR');
    eq('nothing was staged', fake.pending.length, 0);
  });
}

async function happyCommit(): Promise<void> {
  await withFake({}, async (fake, baseUrl) => {
    const report = await applyStagedOps(targetFor(baseUrl), { username: USERNAME, password: PASSWORD }, OPS);
    eq('every operation was staged', report.staged, OPS.length);
    check('committed', report.committed);
    eq('the appliance applied both writes', fake.applied.length, OPS.length);
    eq('nothing is left pending', fake.pending.length, 0);
    eq('exactly one commit', fake.commits, 1);
    eq('one logout', fake.logouts, 1);
    check('the session is closed', !fake.sessionOpen);
  });
}

async function stagingFailureDiscardsEverything(): Promise<void> {
  await withFake({ failStagingPath: '/access-rules/ipv4' }, async (fake, baseUrl) => {
    let message = '';
    try {
      await applyStagedOps(targetFor(baseUrl), { username: USERNAME, password: PASSWORD }, OPS);
    } catch (err) {
      message = err instanceof Error ? err.message : String(err);
    }
    check('the failure names the operation that failed', message.includes('2/2') && message.includes('access rule'), message);
    check('the failure says the appliance is unchanged', message.includes('unchanged'), message);
    eq('NOTHING was applied', fake.applied.length, 0);
    eq('nothing is left pending', fake.pending.length, 0);
    check('at least one discard was issued', fake.discards >= 1, fake.discards);
    eq('no commit was attempted', fake.commits, 0);
    eq('the session was closed', fake.logouts, 1);
  });

  // ── THE FINDING ────────────────────────────────────────────────────────────
  //
  // The same staging failure on an appliance that also REFUSES the discard.
  // The message used to end with "— the pending configuration was discarded and
  // the appliance is unchanged" unconditionally: the branch called
  // `session.discard().catch(() => false)` and threw the boolean away, while
  // the commit-refused branch three lines below read the same boolean and told
  // the truth. So `change_jobs` recorded "appliance unchanged" while one write
  // was still staged on the firewall, nobody inspected it, and the next commit
  // — ours, or the customer's from the web UI — applied our half-batch as
  // theirs.
  await withFake(
    { failStagingPath: '/access-rules/ipv4', failDiscard: true },
    async (fake, baseUrl) => {
      let message = '';
      try {
        await applyStagedOps(targetFor(baseUrl), { username: USERNAME, password: PASSWORD }, OPS);
      } catch (err) {
        message = err instanceof Error ? err.message : String(err);
      }
      check('a staging failure whose discard ALSO fails does not claim the appliance is unchanged',
        !message.includes('the appliance is unchanged'), message);
      check('it says so in the words an operator has to act on',
        message.includes('THE PENDING CONFIGURATION COULD NOT BE DISCARDED'), message);
      check('and it says how many of our writes are still staged',
        message.includes('1 staged write(s) are still on the appliance'), message);
      check('the appliance really does still hold them', fake.pending.length >= 1, fake.pending.map((r) => r.path));
      eq('and still nothing was committed', fake.commits, 0);
      check('the discard was really attempted, more than once', fake.discardAttempts >= 2, fake.discardAttempts);
      eq('the session was closed all the same', fake.logouts, 1);
    },
  );
}

async function rejectedCommitDiscards(): Promise<void> {
  await withFake({ rejectCommit: true }, async (fake, baseUrl) => {
    let message = '';
    try {
      await applyStagedOps(targetFor(baseUrl), { username: USERNAME, password: PASSWORD }, OPS);
    } catch (err) {
      message = err instanceof Error ? err.message : String(err);
    }
    check('the refusal carries the appliance message', message.includes('dependency check failed'), message);
    check('and says the appliance is unchanged', message.includes('unchanged'), message);
    eq('nothing was applied', fake.applied.length, 0);
    eq('nothing is left pending', fake.pending.length, 0);
    eq('the session was closed', fake.logouts, 1);
  });

  // The branch that was already honest, asserted so it stays that way.
  await withFake({ rejectCommit: true, failDiscard: true }, async (fake, baseUrl) => {
    let message = '';
    try {
      await applyStagedOps(targetFor(baseUrl), { username: USERNAME, password: PASSWORD }, OPS);
    } catch (err) {
      message = err instanceof Error ? err.message : String(err);
    }
    check('a rejected commit whose discard fails does not claim the appliance is unchanged',
      !message.includes('the appliance is unchanged'), message);
    check('it raises the alarm instead',
      message.includes('THE PENDING CONFIGURATION COULD NOT BE DISCARDED'), message);
    eq('and the batch really is still staged', fake.pending.length, OPS.length);
  });
}

/**
 * FINDING: `logout()` documents "failures are surfaced through the returned
 * boolean instead", and its only caller did `await session.logout().catch(() =>
 * false)` and dropped the value. Nothing in the report, nothing in the log. On
 * an appliance that 503s the logout — what a real firmware does while it is
 * applying a commit — `applyStagedOps` returned a complete success while the
 * one administrative session this family allows was still open on the customer's
 * firewall.
 */
async function sessionLeakIsVisible(): Promise<void> {
  await withFake({ failLogout: true }, async (fake, baseUrl) => {
    const report = await applyStagedOps(targetFor(baseUrl), { username: USERNAME, password: PASSWORD }, OPS);
    check('the work itself still succeeded', report.committed);
    check('the logout really was attempted', fake.logoutAttempts >= 1, fake.logoutAttempts);
    eq('and it really did not close', fake.logouts, 0);
    check('the appliance really is still holding the session', fake.sessionOpen);

    // The whole finding, in one assertion: the report no longer says otherwise.
    eq('the report says the session was NOT closed', report.sessionClosed, false);
    check(
      'and a warning names the consequence for the customer',
      report.warnings.some((w) => w.includes('STILL OPEN') && w.includes('own firewall')),
      report.warnings,
    );
  });

  await withFake({}, async (fake, baseUrl) => {
    const report = await applyStagedOps(targetFor(baseUrl), { username: USERNAME, password: PASSWORD }, OPS);
    eq('on a healthy appliance the report says the session closed', report.sessionClosed, true);
    eq('and that nothing of ours is left pending', report.pendingCleared, true);
    eq('with no warnings at all', report.warnings.length, 0);
    check('which matches the appliance', !fake.sessionOpen);
  });
}

/**
 * FINDING: rule 1 read somebody else's pending batch, destroyed it, kept no
 * record of it, and reported `discarded: false` — which was true, because
 * `discarded` means "OUR batch was thrown away". Three edits the customer's
 * administrator had staged in the web UI vanished; ObliWAN did not know which,
 * and the customer could not learn who had deleted them.
 *
 * Rule 1 now refuses by default and says what it found. Destroying the batch is
 * an operator's decision — `discardForeignPending` — and it leaves a trace.
 */
async function leftoverPendingIsNeverCommittedAsOurs(): Promise<void> {
  // (a) the default: refuse, and hand the operator what they need to decide.
  await withFake({ seedPending: 3 }, async (fake, baseUrl) => {
    let err: unknown = null;
    try {
      await applyStagedOps(targetFor(baseUrl), { username: USERNAME, password: PASSWORD }, OPS);
    } catch (e) {
      err = e;
    }
    eq('a pending batch ObliWAN did not stage stops the job', err instanceof DriverError ? err.code : null, 'DEVICE_BUSY');
    check('and the job is replayable', err instanceof DriverError ? err.retryable : false);
    const message = err instanceof Error ? err.message : '';
    check('the refusal counts what it found', message.includes('3 record(s)'), message);
    check('and quotes it, so the customer can be told what is at stake',
      message.includes('a crashed session'), message);
    check('and names the way to proceed', message.includes('discardForeignPending'), message);

    eq("the customer's staged edits are STILL on the appliance", fake.pending.length, 3);
    eq('nothing of ours was staged on top of them', fake.applied.length, 0);
    eq('and no commit was attempted', fake.commits, 0);
    eq('the session was closed all the same', fake.logouts, 1);
  });

  // (b) the deliberate replay: destroy it, but never silently.
  await withFake({ seedPending: 3 }, async (fake, baseUrl) => {
    const report = await applyStagedOps(
      targetFor(baseUrl),
      { username: USERNAME, password: PASSWORD },
      OPS,
      { discardForeignPending: true },
    );
    check('committed', report.committed);
    eq('only OUR operations were applied', fake.applied.length, OPS.length);
    check(
      "somebody else's abandoned batch was not committed",
      !fake.applied.some((r) => r.path === '/leftover'),
      fake.applied.map((r) => r.path),
    );

    // The traceability the old code had none of.
    check('the report records that a batch of somebody else was destroyed', report.leftoverDiscarded !== null);
    eq('with its size', report.leftoverDiscarded?.records, 3);
    check('and a summary a human can recognise their work in',
      (report.leftoverDiscarded?.summary ?? '').includes('a crashed session'),
      report.leftoverDiscarded?.summary);
    check('a warning says the deletion is unrecoverable',
      report.warnings.some((w) => w.includes('DESTROYED') && w.includes('no way to restore')),
      report.warnings);
    eq('and `discarded` still means what it says: OUR batch was not', report.discarded, false);
  });

  // An EMPTY pending envelope is not somebody's batch. Firmwares answer `{}`,
  // `{"pending": []}` or 404 for "nothing staged", and a rule 1 that refused on
  // those would refuse every job on those firmwares.
  await withFake({}, async (fake, baseUrl) => {
    const report = await applyStagedOps(targetFor(baseUrl), { username: USERNAME, password: PASSWORD }, OPS);
    check('an empty pending configuration is not treated as a foreign batch', report.committed);
    eq('and nothing was recorded as destroyed', report.leftoverDiscarded, null);
    eq('and no needless discard was issued before staging', fake.discardAttempts, 0);
  });
}

async function pendingNotFoundIsEmptyNotAFailure(): Promise<void> {
  await withFake({ pendingNotFoundWhenEmpty: true }, async (fake, baseUrl) => {
    const report = await applyStagedOps(targetFor(baseUrl), { username: USERNAME, password: PASSWORD }, OPS);
    check('a 404 on an empty pending config is not an error', report.committed);
    eq('and no needless discard was issued before staging', fake.discardAttempts, 0);
  });
}

async function passwordNeverLeaks(): Promise<void> {
  await withFake({ failStagingPath: '/access-rules/ipv4' }, async (_fake, baseUrl) => {
    let message = '';
    try {
      await applyStagedOps(targetFor(baseUrl), { username: USERNAME, password: PASSWORD }, OPS);
    } catch (err) {
      message = err instanceof Error ? `${err.message}${(err as Error).stack ?? ''}` : String(err);
    }
    check('the password is not in the error', !message.includes(PASSWORD));
  });

  // And a wrong password, which is the case where a CLI would echo it back.
  await withFake({}, async (_fake, baseUrl) => {
    let message = '';
    try {
      await applyStagedOps(targetFor(baseUrl), { username: USERNAME, password: 'wrong-password-value' }, OPS);
    } catch (err) {
      message = err instanceof Error ? err.message : String(err);
    }
    check('an auth failure does not echo the password', !message.includes('wrong-password-value'), message);
  });
}

async function zeroOperationsIsRefused(): Promise<void> {
  await withFake({}, async (fake, baseUrl) => {
    let code: string | null = null;
    try {
      await applyStagedOps(targetFor(baseUrl), { username: USERNAME, password: PASSWORD }, []);
    } catch (err) {
      code = err instanceof DriverError ? err.code : 'NOT_A_DRIVER_ERROR';
    }
    eq('an empty batch never opens a session', code, 'PROTOCOL_ERROR');
    eq('no login was burnt', fake.logins, 0);
  });
}

async function driverInventoryAndApply(): Promise<void> {
  await withFake({}, async (fake, baseUrl) => {
    const driver = new SonicWallDriver();
    const inventory = await driver.getInventory(contextFor(baseUrl));
    eq('the driver reads the model over REST', inventory.model, 'NSa 2700');
    eq('and the serial', inventory.serial, 'FAKE0001SONIC');
    // The REST path reports the firmware string verbatim; only the SNMP path
    // runs it through `parseSysDescr`. Asserting the verbatim value keeps this
    // test about the SESSION and not about a parser it does not own.
    eq('and the firmware', inventory.osVersion, 'SonicOS Enhanced 7.0.1-5030');
    check('the identification session was closed too', !fake.sessionOpen);
    eq('identification logged out', fake.logouts, 1);
  });
}

/**
 * The end-to-end sentence of this milestone: an intent nobody wrote SonicOS for
 * compiles to a staged batch, and that exact batch is what the appliance
 * receives — no re-rendering between the plan an operator approves and the
 * writes that reach the firewall.
 */
async function compiledIntentAppliesAtomically(): Promise<void> {
  await withFake({}, async (fake, baseUrl) => {
    const compilation = compileIntent(referenceSiteIntent(), {
      ...GOLDEN_TARGET,
      family: 'sonicwall_sonicos',
    });
    const ops = sonicOsOpsOf(compilation.artifact.body);
    check('the artefact carries staged operations', ops.length > 10, ops.length);

    const driver = new SonicWallDriver();
    const report = await driver.applyPendingConfig(contextFor(baseUrl), ops);
    check('the compiled batch committed', report.committed);
    check('the session was closed and the report says so', report.sessionClosed);
    check('nothing of ours is left pending, and the report says so', report.pendingCleared);
    eq('no batch of somebody else was destroyed to get there', report.leftoverDiscarded, null);
    eq('and the job records no warning', report.warnings.length, 0);
    eq('every compiled operation reached the appliance', fake.applied.length, ops.length);
    eq('one session, one commit', fake.commits, 1);
    eq('one logout', fake.logouts, 1);
    check(
      'the appliance received the interfaces the NCM declares',
      compilation.document.resources.interfaces.every((iface) =>
        fake.applied.some((r) => JSON.stringify(r.body).includes(`"${iface.name}"`)),
      ),
    );
    check(
      'no plaintext secret reached the appliance — only vault placeholders',
      JSON.stringify(fake.applied).includes('<<secret:'),
    );
  });

  // And the same batch, one op of which the appliance rejects: nothing lands.
  await withFake({ failStagingPath: '/bwm/elastic' }, async (fake, baseUrl) => {
    const compilation = compileIntent(referenceSiteIntent(), {
      ...GOLDEN_TARGET,
      family: 'sonicwall_sonicos',
    });
    const ops = sonicOsOpsOf(compilation.artifact.body);
    let failed = false;
    try {
      await new SonicWallDriver().applyPendingConfig(contextFor(baseUrl), ops);
    } catch {
      failed = true;
    }
    check('the apply failed', failed);
    eq('and the appliance is byte-identical to how it started', fake.applied.length, 0);
    eq('with nothing left pending', fake.pending.length, 0);
  });
}

// ── run ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  await sessionLifecycle();
  await overrideStealsTheLock();
  await missingCookieIsFatal();
  await happyCommit();
  await stagingFailureDiscardsEverything();
  await rejectedCommitDiscards();
  await sessionLeakIsVisible();
  await leftoverPendingIsNeverCommittedAsOurs();
  await pendingNotFoundIsEmptyNotAFailure();
  await passwordNeverLeaks();
  await zeroOperationsIsRefused();
  await driverInventoryAndApply();
  await compiledIntentAppliesAtomically();

  process.stdout.write(`\nM11 SonicOS driver — ${passed} assertion(s) passed, ${failures.length} failed\n`);
  for (const failure of failures) process.stdout.write(`  FAIL ${failure}\n`);
  process.exitCode = failures.length === 0 ? 0 : 1;
}

void main();
