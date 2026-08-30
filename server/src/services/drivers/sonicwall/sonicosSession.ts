// ============================================================================
// ObliWAN — SonicOS configuration session: staging, atomic commit, discard
// ============================================================================
//
// ┌─ THE FAILURE MODE THIS FILE EXISTS TO PREVENT ────────────────────────────┐
// │ A SonicWall allows a very small number of concurrent administrative       │
// │ sessions and it LEAKS them on timeout. Leave one open and, within a day,  │
// │ nobody can log into the customer's firewall — not our poller, not the     │
// │ customer's own administrator, not the person trying to fix it.            │
// │                                                                           │
// │ So: `login()` happens once, the work happens, and `logout()` runs in a    │
// │ `finally`, unconditionally, even when the work threw, even when the       │
// │ commit failed, even when the process is on its way out. Losing the        │
// │ original error's stack is a cheaper accident than losing the firewall.    │
// │                                                                           │
// │ `override: true` on login steals the configuration lock from a stale      │
// │ web-UI session. Without it, one forgotten browser tab blocks ObliWAN      │
// │ indefinitely; with it, ObliWAN is the one who can block the customer —    │
// │ which is why the session is held for the shortest possible time and       │
// │ NEVER across two operations.                                              │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ THE PENDING CONFIGURATION, AND WHY IT MAKES SONICWALL THE SAFEST BRAND ──┐
// │ SonicOS writes do not take effect when they are sent. They accumulate in  │
// │ a PENDING configuration and take effect on `POST config/pending`. A       │
// │ `DELETE config/pending` throws the whole batch away and leaves the        │
// │ appliance byte-identical to what it was.                                  │
// │                                                                           │
// │ Three rules follow, and all three are enforced below rather than          │
// │ documented as advice:                                                     │
// │                                                                           │
// │  1. NEVER STAGE ON TOP OF A BATCH THAT IS NOT OURS. A pending             │
// │     configuration left behind by a crashed session — ours or the          │
// │     customer's — would be committed along with ours. Committing           │
// │     somebody else's half-finished edit is the worst thing this module     │
// │     could do, and it would look like our change.                          │
// │                                                                           │
// │     This rule USED to discard that batch on sight, silently. That is a    │
// │     second way to destroy the customer's work: three edits their          │
// │     administrator had staged in the web UI vanished, the report said      │
// │     `discarded: false` (true — that field means OUR batch), and nobody    │
// │     could learn ObliWAN had deleted them. The job now STOPS with          │
// │     `DEVICE_BUSY` and quotes what it found; destroying the batch is a     │
// │     replay an operator asks for (`discardForeignPending`), recorded in    │
// │     `leftoverDiscarded` and in a warning the change job copies.           │
// │                                                                           │
// │  2. ANY staging failure discards EVERYTHING. There is no "commit what we  │
// │     managed to stage": a firewall with the address objects of a policy    │
// │     and not the policy is a configuration nobody designed.                │
// │                                                                           │
// │  3. A failed commit discards too. SonicOS validates on commit; a          │
// │     rejected commit that leaves the batch pending arms a trap for the     │
// │     next person who commits anything at all.                              │
// │                                                                           │
// │  And the rule that binds 2 and 3: WHEN A DISCARD FAILS, SAY SO. Both      │
// │     paths call `discard()`, which reports failure by returning `false`    │
// │     rather than throwing. Rule 2 used to drop that boolean and tell the   │
// │     change job "the appliance is unchanged" regardless — while our        │
// │     half-batch sat on the firewall, waiting for the next commit to        │
// │     apply it as somebody else's change. A guarantee asserted on the       │
// │     path where it does not hold is worse than no guarantee.               │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ D3 ──────────────────────────────────────────────────────────────────────┐
// │ Nothing in this file is reachable from a controller. The only production  │
// │ caller of `applyStagedOps` will be the M6 apply path, which runs inside a │
// │ `change_jobs` row with a device lock, a frozen plan, a management-path    │
// │ guard verdict and a pre-change backup. Today its callers are the M11      │
// │ self-test and the fake appliance it runs against.                         │
// └───────────────────────────────────────────────────────────────────────────┘

import { logger } from '../../../utils/logger';
import { DriverError, redact } from '../types';
import {
  RestTransport,
  httpError,
  type RestTarget,
} from '../../transport/rest.transport';

/** SonicOS REST prefix. Every path below is relative to it. */
export const SONICOS_API_PREFIX = '/api/sonicos';

/** The pending-configuration endpoint: POST commits it, DELETE throws it away. */
export const SONICOS_PENDING_PATH = '/config/pending';

export interface SonicOsCredentials {
  username: string;
  password: string;
}

/**
 * One staged write. This is exactly the shape the intent compiler emits for
 * `artifactFormat: 'sonicos_rest'`, so the artefact an operator reviews on the
 * plan screen and the request this module sends are the same object.
 */
export interface SonicOsStagedOp {
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** Relative to `SONICOS_API_PREFIX`, e.g. `/address-objects/ipv4`. */
  path: string;
  body?: unknown;
  /** Human label carried into the audit trail. Never a secret. */
  description?: string;
}

/**
 * What a change job records about one SonicOS write.
 *
 * ┌─ EVERY FIELD BELOW IS HERE BECAUSE ITS ABSENCE HID A REAL FAILURE ────────┐
 * │ `staged` / `committed` / `discarded` describe OUR batch, and on their own │
 * │ they let three different appliance states report as one clean success:    │
 * │                                                                          │
 * │  · the administrative session was never closed — `logout()` returned      │
 * │    `false` into a `.catch(() => false)` nobody read. `maxConcurrent`      │
 * │    `Sessions` is 1 for this family, so the customer cannot log into their │
 * │    own firewall any more and nothing in the job says why.                 │
 * │    -> `sessionClosed`.                                                    │
 * │                                                                          │
 * │  · our own half-batch was left staged because the cleanup discard also    │
 * │    failed. The next commit — ours, or the customer's from the web UI —    │
 * │    applies it, and it looks like their change.                            │
 * │    -> `pendingCleared`.                                                   │
 * │                                                                          │
 * │  · rule 1 destroyed a pending batch that was NOT ours: three edits the    │
 * │    customer's administrator had staged in the web UI. `discarded` means   │
 * │    "OUR batch was thrown away", so it read `false`, and the only record   │
 * │    of the deletion was that it never existed.                             │
 * │    -> `leftoverDiscarded`.                                                │
 * │                                                                          │
 * │ `warnings` is the copy the change job shows a human. A boolean nobody     │
 * │ renders is the same dead guard as a boolean nobody returns.               │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export interface SonicOsApplyReport {
  staged: number;
  committed: boolean;
  /** OUR batch was thrown away. Never about somebody else's — see
   *  `leftoverDiscarded`. */
  discarded: boolean;
  /** Whatever the appliance answered to the commit, for the audit trail. */
  commitDetail: string | null;
  /** `DELETE /auth` was accepted: the one administrative slot is free again. */
  sessionClosed: boolean;
  /** Nothing of ours is left staged: either nothing was, or the discard in the
   *  `finally` was accepted. */
  pendingCleared: boolean;
  /** A pending batch found on the appliance BEFORE we staged anything, and
   *  destroyed by rule 1. `null` when there was none — which is the normal
   *  case and the only one that used to be representable. */
  leftoverDiscarded: LeftoverPending | null;
  /** Human-readable copy for `change_jobs`. Empty on a clean run. */
  warnings: string[];
}

/**
 * Somebody else's unapplied configuration, as much of it as we can carry into
 * the audit trail.
 *
 * It is not a backup and it cannot be replayed: SonicOS gives no way to
 * re-stage a batch we have thrown away. It is evidence — enough for the
 * customer's administrator to be told WHAT of theirs ObliWAN deleted, which is
 * the thing they could not learn before.
 */
export interface LeftoverPending {
  /** Number of records the pending document held, when it is countable. */
  records: number | null;
  /** The pending body, JSON-serialized and truncated. Never a secret: the
   *  pending configuration of a firewall can hold one, so it is passed through
   *  `redact` with the session password before it is stored. */
  summary: string;
}

/** How `applyStagedOps` treats a pending batch it did not stage (rule 1). */
export interface ApplyStagedOptions {
  /**
   * `false` (the default) — REFUSE. A pending batch nobody can attribute is
   * three unapplied edits of the customer's administrator until proven
   * otherwise, and destroying them silently is what this option exists to stop.
   * The job fails with `DEVICE_BUSY`, which is retryable, and the error carries
   * the summary so an operator can decide.
   *
   * `true` — DISCARD IT AND SAY SO. What an operator sets on the replay, once
   * they have read the summary and decided the batch was ours or is expendable.
   * The report then carries `leftoverDiscarded` and a warning.
   *
   * There is no third option: committing it along with ours is the worst thing
   * this module could do, and it would look like our change.
   */
  discardForeignPending?: boolean;
}

/**
 * An authenticated SonicOS session.
 *
 * Never constructed directly by a caller: `withSonicOsConfigSession` is the
 * only supported entry point, because it is the thing that owns the `finally`.
 */
export class SonicOsConfigSession {
  private cookie: string | null = null;
  private csrf: string | null = null;
  /** Number of writes staged since the last commit or discard. */
  private pendingOps = 0;

  constructor(
    private readonly rest: RestTransport,
    private readonly creds: SonicOsCredentials,
  ) {}

  get isAuthenticated(): boolean {
    return this.cookie !== null;
  }

  get stagedCount(): number {
    return this.pendingOps;
  }

  private headers(extra: Record<string, string> = {}): Record<string, string> {
    return {
      Accept: 'application/json',
      ...(this.cookie ? { Cookie: this.cookie } : {}),
      // SonicOS 7 hands out a CSRF token with the session and rejects writes
      // without it. Absent on 6.5, which is why it is conditional rather than
      // required — the difference between the two firmwares is a probed fact,
      // not a family split (see shared/device.ts).
      ...(this.csrf ? { 'X-CSRF-Token': this.csrf } : {}),
      ...extra,
    };
  }

  /** POST /auth with `override: true`. Idempotent from our side: a second call
   *  on a live session would burn a second slot, so it refuses instead. */
  async login(): Promise<void> {
    if (this.cookie) {
      throw new DriverError('SonicOS session is already authenticated', 'PROTOCOL_ERROR', {
        transport: 'rest',
        retryable: false,
      });
    }
    const basic = Buffer.from(`${this.creds.username}:${this.creds.password}`).toString('base64');
    const res = await this.rest.request<Record<string, unknown>>(
      'POST',
      `${SONICOS_API_PREFIX}/auth`,
      {
        headers: { Authorization: `Basic ${basic}`, 'Content-Type': 'application/json' },
        body: { override: true },
        idempotent: false,
      },
    );
    if (res.statusCode >= 400) throw httpError(res.statusCode, '', 'sonicos/auth');

    const setCookie = res.headers['set-cookie'];
    const cookie = Array.isArray(setCookie) ? setCookie.join('; ') : (setCookie ?? null);
    if (!cookie) {
      throw new DriverError(
        'SonicOS accepted the login but returned no session cookie',
        'PROTOCOL_ERROR',
        { transport: 'rest', retryable: false },
      );
    }
    // Keep only the name=value pairs; a `Path=/; HttpOnly` echoed back as a
    // request cookie is what makes some firmwares 400 the next call.
    this.cookie = cookie
      .split(',')
      .map((part) => part.split(';')[0].trim())
      .filter((part) => part.includes('='))
      .join('; ');

    const token = res.body && typeof res.body === 'object' ? (res.body as Record<string, unknown>) : {};
    const csrf = token.csrfToken ?? token.csrf_token ?? null;
    this.csrf = typeof csrf === 'string' && csrf.length > 0 ? csrf : null;
  }

  /**
   * DELETE /auth. Swallows nothing and reports nothing: the CALLER is a
   * `finally`, and an exception thrown out of a `finally` replaces the real
   * error. Failures are surfaced through the returned boolean instead — read by
   * `withSonicOsConfigSession`'s `finally`, turned into `SonicOsSessionCleanup
   * .sessionClosed`, logged at `error`, and carried into
   * `SonicOsApplyReport.sessionClosed` and `.warnings`. A boolean with no
   * consumer would be a dead guard, and this one was for a while.
   */
  async logout(): Promise<boolean> {
    if (!this.cookie) return true;
    try {
      const res = await this.rest.request('DELETE', `${SONICOS_API_PREFIX}/auth`, {
        headers: this.headers(),
        expect: 'none',
        idempotent: true,
      });
      return res.statusCode < 400;
    } catch {
      return false;
    } finally {
      this.cookie = null;
      this.csrf = null;
    }
  }

  /**
   * Stage ONE write. It does not take effect: it lands in the pending
   * configuration and waits for `commit()`.
   *
   * `idempotent: false` on purpose — the REST transport retries GETs, and
   * retrying a staged POST is how one address object becomes two.
   */
  async stage(op: SonicOsStagedOp): Promise<void> {
    this.requireSession(op.path);
    const res = await this.rest.request<unknown>(op.method, `${SONICOS_API_PREFIX}${op.path}`, {
      headers: this.headers({ 'Content-Type': 'application/json' }),
      body: op.body,
      expect: 'json',
      idempotent: false,
    });
    if (res.statusCode >= 400) {
      throw httpError(
        res.statusCode,
        describeSonicOsError(res.body),
        `${op.method} sonicos${op.path}${op.description ? ` (${op.description})` : ''}`,
      );
    }
    this.pendingOps += 1;
  }

  /** What the appliance currently holds unapplied. Read before staging so a
   *  batch left behind by somebody else is never committed as ours. */
  async pending(): Promise<unknown> {
    this.requireSession(SONICOS_PENDING_PATH);
    const res = await this.rest.request<unknown>(
      'GET',
      `${SONICOS_API_PREFIX}${SONICOS_PENDING_PATH}`,
      { headers: this.headers() },
    );
    // A firmware with nothing pending answers 404 on some builds. That is an
    // empty pending configuration, not a failure.
    if (res.statusCode === 404) return null;
    if (res.statusCode >= 400) throw httpError(res.statusCode, '', 'sonicos/config/pending');
    return res.body ?? null;
  }

  /** All or nothing. A rejected commit leaves the appliance untouched. */
  async commit(): Promise<string | null> {
    this.requireSession(SONICOS_PENDING_PATH);
    const res = await this.rest.request<unknown>(
      'POST',
      `${SONICOS_API_PREFIX}${SONICOS_PENDING_PATH}`,
      { headers: this.headers({ 'Content-Type': 'application/json' }), body: {}, idempotent: false },
    );
    if (res.statusCode >= 400) {
      throw httpError(res.statusCode, describeSonicOsError(res.body), 'sonicos/config/pending');
    }
    this.pendingOps = 0;
    return describeSonicOsError(res.body) || null;
  }

  /** Throw the pending configuration away. Reports success rather than
   *  throwing, for the same `finally` reason as `logout`. */
  async discard(): Promise<boolean> {
    if (!this.cookie) return true;
    try {
      const res = await this.rest.request('DELETE', `${SONICOS_API_PREFIX}${SONICOS_PENDING_PATH}`, {
        headers: this.headers(),
        expect: 'none',
        idempotent: true,
      });
      // 404 = nothing was pending, which is the state we wanted.
      const ok = res.statusCode < 400 || res.statusCode === 404;
      if (ok) this.pendingOps = 0;
      return ok;
    } catch {
      return false;
    }
  }

  private requireSession(path: string): void {
    if (!this.cookie) {
      throw new DriverError(
        `SonicOS request to ${path} attempted without a session`,
        'AUTH_FAILED',
        { transport: 'rest', retryable: false },
      );
    }
  }
}

/** SonicOS answers `{ status: { info: [{ message: "..." }] } }` on both success
 *  and failure. Flattened here so the message reaches the audit trail instead
 *  of a bare status code. */
export function describeSonicOsError(body: unknown): string {
  if (!body || typeof body !== 'object') return '';
  const status = (body as Record<string, unknown>).status;
  const info = status && typeof status === 'object' ? (status as Record<string, unknown>).info : null;
  if (!Array.isArray(info)) return '';
  return info
    .map((entry) => {
      if (!entry || typeof entry !== 'object') return '';
      const message = (entry as Record<string, unknown>).message;
      return typeof message === 'string' ? message : '';
    })
    .filter((s) => s.length > 0)
    .join('; ')
    .slice(0, 400);
}

/**
 * What the `finally` of `withSonicOsConfigSession` managed to do.
 *
 * `logout()` and `discard()` report failure by returning `false` rather than by
 * throwing, because throwing out of a `finally` replaces the real error. That
 * choice is only honest if somebody READS the boolean: for a while nobody did —
 * both values went into `.catch(() => false)` and were dropped on the floor, so
 * a session left open on the customer's firewall was reported as a complete
 * success. This object is the consumer.
 */
export interface SonicOsSessionCleanup {
  /** `DELETE /auth` was accepted, or there was no session to close. */
  sessionClosed: boolean;
  /** Nothing of ours was left staged. */
  pendingCleared: boolean;
  /** `DELETE config/pending` calls the cleanup made (0 when nothing was
   *  staged). Each one is retried by the transport; this counts the calls. */
  discardAttempts: number;
}

/**
 * Log in, run the work, log out — the logout in a `finally`, unconditionally,
 * and a discard of anything still pending BEFORE it.
 *
 * The two cleanups are separate `await`s with their own `catch`, because a
 * failing discard must not stop the logout from happening: an appliance with a
 * stray pending batch is recoverable, an appliance nobody can log into is a
 * site visit.
 *
 * `onCleanup` is how the outcome of those two `catch`es leaves the function.
 * It runs inside the `finally`, after both, and it may not throw — anything it
 * raises is swallowed here, because the caller's error is worth more than the
 * bookkeeping. It is called on EVERY path, including the one where `fn` threw.
 */
export async function withSonicOsConfigSession<T>(
  target: RestTarget,
  creds: SonicOsCredentials,
  fn: (session: SonicOsConfigSession) => Promise<T>,
  onCleanup?: (outcome: SonicOsSessionCleanup) => void,
): Promise<T> {
  const rest = new RestTransport({
    ...target,
    secrets: [...(target.secrets ?? []), creds.password],
  });
  const session = new SonicOsConfigSession(rest, creds);
  const outcome: SonicOsSessionCleanup = {
    sessionClosed: false,
    pendingCleared: true,
    discardAttempts: 0,
  };
  try {
    await session.login();
    return await fn(session);
  } finally {
    if (session.stagedCount > 0) {
      outcome.discardAttempts += 1;
      outcome.pendingCleared = await session.discard().catch(() => false);
    }
    outcome.sessionClosed = await session.logout().catch(() => false);
    await rest.close().catch(() => undefined);

    // The guarantee this whole file exists to provide, and the two ways it can
    // fail. Neither may be silent: a firewall nobody can log into is a site
    // visit, and a stray half-batch is a trap armed for the next commit.
    if (!outcome.sessionClosed) {
      logger.error(
        { host: target.baseUrl },
        'SonicOS logout failed — an administrative session is STILL OPEN on the appliance; ' +
          'this family allows one at a time, so the customer may be locked out of their own firewall',
      );
    }
    if (!outcome.pendingCleared) {
      logger.error(
        { host: target.baseUrl, discardAttempts: outcome.discardAttempts },
        'SonicOS discard failed — OUR staged writes are still pending on the appliance and will be ' +
          'applied by whoever commits next; inspect the appliance before the next change',
      );
    }
    try {
      onCleanup?.(outcome);
    } catch {
      // A bookkeeping callback may not replace the caller's error.
    }
  }
}

/**
 * The whole write path, in one call: account for whatever was left pending,
 * stage every operation, commit once.
 *
 * Any failure at any point leaves the appliance exactly as it was found — and
 * when it does NOT, the report and the error say so in those words rather than
 * asserting the reassuring version. The report is what the change job records.
 */
export async function applyStagedOps(
  target: RestTarget,
  creds: SonicOsCredentials,
  ops: readonly SonicOsStagedOp[],
  options: ApplyStagedOptions = {},
): Promise<SonicOsApplyReport> {
  if (ops.length === 0) {
    throw new DriverError('refusing to open a SonicOS session for zero operations', 'PROTOCOL_ERROR', {
      transport: 'rest',
      retryable: false,
    });
  }

  let cleanup: SonicOsSessionCleanup = {
    sessionClosed: false,
    pendingCleared: false,
    discardAttempts: 0,
  };
  const warnings: string[] = [];
  let leftoverDiscarded: LeftoverPending | null = null;

  const inner = await withSonicOsConfigSession(
    target,
    creds,
    async (session) => {
      // ── Rule 1: never commit somebody else's abandoned batch ──────────────
      //
      // The old code read the leftover, threw the value away, discarded the
      // batch and reported `discarded: false` — which means "our batch was not
      // discarded" and was true. Three edits the customer's administrator had
      // staged in the web UI disappeared, ObliWAN did not know which, and the
      // customer could not learn that ObliWAN had done it.
      //
      // So the batch is described first, and destroying it is now a decision
      // an operator makes rather than a side effect of starting a job.
      const leftover = await session.pending();
      if (!isPendingEmpty(leftover)) {
        const described = describePending(leftover, creds.password);
        if (!options.discardForeignPending) {
          throw new DriverError(
            `SonicOS holds a pending configuration that ObliWAN did not stage ` +
              `(${described.records ?? 'an unknown number of'} record(s)): ${described.summary} — ` +
              'refusing to stage on top of it or to destroy it. Committing it would apply ' +
              "somebody else's half-finished edit as ours; discarding it would delete work " +
              'nobody can get back. Inspect the appliance, then replay this job with ' +
              'discardForeignPending once the batch is known to be expendable.',
            'DEVICE_BUSY',
            { transport: 'rest', retryable: true },
          );
        }
        const cleared = await session.discard();
        if (!cleared) {
          throw new DriverError(
            'SonicOS holds a pending configuration that could not be discarded; refusing to stage on top of it',
            'DEVICE_BUSY',
            { transport: 'rest', retryable: true },
          );
        }
        leftoverDiscarded = described;
        warnings.push(
          `DESTROYED a pending configuration ObliWAN did not stage: ` +
            `${described.records ?? 'an unknown number of'} record(s) — ${described.summary}. ` +
            'SonicOS offers no way to restore it; tell the site administrator before they look for it.',
        );
        logger.warn(
          { host: target.baseUrl, records: described.records },
          'SonicOS: rule 1 destroyed a pending configuration staged by somebody else',
        );
      }

      let staged = 0;
      try {
        for (const op of ops) {
          await session.stage(op);
          staged += 1;
        }
      } catch (err) {
        // Rule 2: a partial batch is never committed — and if the discard that
        // enforces that also fails, the message says THAT, not "unchanged".
        // Claiming an appliance is unchanged when half a batch is still staged
        // on it is how our half-batch ends up applied by the customer's next
        // commit and read as their change.
        const discarded = await session.discard().catch(() => false);
        throw new DriverError(
          `SonicOS staging failed at operation ${staged + 1}/${ops.length}` +
            `${ops[staged]?.description ? ` (${ops[staged].description})` : ''}: ` +
            `${redact(err instanceof Error ? err.message : String(err), [creds.password])}` +
            `${
              discarded
                ? ' — the pending configuration was discarded and the appliance is unchanged'
                : ` — THE PENDING CONFIGURATION COULD NOT BE DISCARDED, ${staged} staged write(s)` +
                  ' are still on the appliance and will be applied by whoever commits next;' +
                  ' inspect the appliance before the next change'
            }`,
          err instanceof DriverError ? err.code : 'PROTOCOL_ERROR',
          { transport: 'rest', retryable: false, cause: err },
        );
      }

      try {
        const detail = await session.commit();
        return { staged, committed: true, discarded: false, commitDetail: detail };
      } catch (err) {
        // Rule 3: a rejected commit does not stay pending.
        const discarded = await session.discard().catch(() => false);
        throw new DriverError(
          `SonicOS refused the commit of ${staged} staged operation(s): ` +
            `${redact(err instanceof Error ? err.message : String(err), [creds.password])}` +
            `${discarded ? ' — the pending configuration was discarded and the appliance is unchanged' : ' — THE PENDING CONFIGURATION COULD NOT BE DISCARDED, inspect the appliance before the next change'}`,
          err instanceof DriverError ? err.code : 'PROTOCOL_ERROR',
          { transport: 'rest', retryable: false, cause: err },
        );
      }
    },
    (outcome) => {
      cleanup = outcome;
    },
  );

  if (!cleanup.sessionClosed) {
    warnings.push(
      'the administrative session could not be closed: it is STILL OPEN on the appliance. ' +
        'This family allows one at a time — the customer may be unable to log into their own firewall.',
    );
  }
  if (!cleanup.pendingCleared) {
    warnings.push(
      'staged writes of ours could not be discarded and are still pending on the appliance; ' +
        'whoever commits next will apply them.',
    );
  }

  return {
    ...inner,
    sessionClosed: cleanup.sessionClosed,
    pendingCleared: cleanup.pendingCleared,
    leftoverDiscarded,
    warnings,
  };
}

/**
 * Is there actually anything staged?
 *
 * Firmwares disagree about how they say "nothing": some 404 (handled in
 * `pending()`), some answer `{ "pending": [] }` with a 200, some `{}`. All
 * three mean the same thing, and reading an empty envelope as somebody
 * else's abandoned batch would make rule 1 refuse every job on those
 * firmwares — a guard that fires on the normal case is a guard that gets
 * turned off.
 *
 * A shape we cannot read at all is NOT treated as empty: an unrecognised
 * body is exactly the case where refusing and asking a human is right.
 */
export function isPendingEmpty(body: unknown): boolean {
  if (body === null || body === undefined) return true;
  if (Array.isArray(body)) return body.length === 0;
  if (typeof body !== 'object') return false;
  const entries = Object.entries(body as Record<string, unknown>);
  if (entries.length === 0) return true;
  return entries.every(([, value]) => {
    if (value === null || value === undefined) return true;
    if (Array.isArray(value)) return value.length === 0;
    if (typeof value === 'object') return Object.keys(value as object).length === 0;
    return false;
  });
}

/**
 * Describe a pending configuration well enough for a human to recognise their
 * own work in it, and no better.
 *
 * The pending document of a firewall can hold a PSK or a local user's password
 * (§8.2), so the summary goes through `redact` with the session password and is
 * truncated hard. It is evidence for an audit trail, not a backup.
 */
function describePending(body: unknown, password: string): LeftoverPending {
  let records: number | null = null;
  if (Array.isArray(body)) {
    records = body.length;
  } else if (body && typeof body === 'object') {
    const pending = (body as Record<string, unknown>).pending;
    if (Array.isArray(pending)) records = pending.length;
  }
  let serialized: string;
  try {
    serialized = JSON.stringify(body) ?? String(body);
  } catch {
    serialized = '(a pending configuration that could not be serialized)';
  }
  const summary = redact(serialized, [password]).slice(0, 600);
  return { records, summary };
}
