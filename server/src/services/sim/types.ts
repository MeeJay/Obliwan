/**
 * ObliWAN F9 — what a mobile partner must be able to do, and what it may not.
 *
 * ┌─ ONE INTERFACE, THREE INGESTION SHAPES, BECAUSE THE PARTNERS DIFFER ──────┐
 * │ Phenix answers an HTTP API we poll. CFAST's portal exposes "Connexions    │
 * │ partenaires → Webhooks / Comptes externes", so the shape to expect there  │
 * │ is a PUSH we receive, not a poll we run. And any partner at all can be    │
 * │ fed from a file exported off its portal.                                  │
 * │                                                                          │
 * │ Writing the interface around `open()` + `listLines()` + `fetchBalances()` │
 * │ — a poll — and bolting push on later would mean rewriting every caller    │
 * │ the day CFAST is understood. `SimConnector.ingestion` declares which of   │
 * │ the three a connector actually implements, the sweep only ever calls a    │
 * │ `pull` connector, and a `push` connector is fed by its own route.         │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ A CONNECTOR REPORTS ABSENCE. IT NEVER INVENTS A ZERO. ───────────────────┐
 * │ Every `*Mb` field below is `number | null`, and `null` is the value a     │
 * │ connector MUST produce when the partner did not answer, answered with a   │
 * │ field it does not recognise, or answered something unparseable.           │
 * │                                                                          │
 * │ This is not defensive style, it is the core requirement. The prototype    │
 * │ this feature replaces read the partner with `(float) ($r['restValueGo']   │
 * │ ?? 0)`, so a renamed field or a partial response became "0 Go remaining"  │
 * │ on every line at once — and 0 remaining is the input that says "buy". A   │
 * │ connector that cannot read a value says so; `evaluateBalance` turns that  │
 * │ into `unknown`, and `unknown` never spends.                               │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * §8.2 — a connector receives decrypted credentials and must ensure they never
 * reach a log, an error message or a stored `sim_sync_runs.error`. `scrub()`
 * below is how, and `SimConnectorError` applies it in its constructor so the
 * discipline does not depend on every throw site remembering.
 */

import type {
  SimAuthMode,
  SimIngestionKind,
  SimLineStatus,
  SimPlatform,
} from '@obliwan/shared';

// ============================================================================
// Errors
// ============================================================================

/**
 * `auth_failed` is separated from `partner_error` on purpose, and the sweep
 * treats them very differently: a bad token means every remaining line in this
 * account will fail the same way, so the sweep STOPS and the account is flagged
 * for a human. A single line erroring is skipped and counted.
 */
export type SimErrorCode =
  | 'AUTH_FAILED'
  | 'PARTNER_ERROR'
  | 'UNREADABLE'
  | 'NOT_IMPLEMENTED'
  | 'CONFIG_ERROR';

/**
 * Removes credential material from a string before it can be logged or stored.
 *
 * Literal replacement rather than a pattern: the only strings we can be sure
 * are secret are the ones we were handed. Short values are skipped — replacing
 * every occurrence of a two-character password would mangle the message into
 * something unreadable, and a two-character password has a bigger problem.
 */
export function scrub(text: string, secrets: ReadonlyArray<string | null | undefined>): string {
  let out = text;
  for (const s of secrets) {
    if (!s || s.length < 6) continue;
    out = out.split(s).join('***');
  }
  return out;
}

export class SimConnectorError extends Error {
  readonly code: SimErrorCode;
  readonly platform: SimPlatform;
  /** HTTP status when the partner produced one. Diagnostic only. */
  readonly statusCode: number | null;

  constructor(
    message: string,
    code: SimErrorCode,
    platform: SimPlatform,
    opts: { statusCode?: number | null; secrets?: ReadonlyArray<string | null | undefined> } = {},
  ) {
    // Scrubbed HERE rather than at each throw site: a rule nobody can forget
    // beats a rule everybody must remember (§8.2).
    super(scrub(message, opts.secrets ?? []));
    this.name = 'SimConnectorError';
    this.code = code;
    this.platform = platform;
    this.statusCode = opts.statusCode ?? null;
  }
}

/**
 * The one predicate the sweep reasons with when deciding whether to STOP.
 *
 * Used by `sync.service` at both decision points — the per-line catch and the
 * account-level catch. It existed with no caller in the first draft while both
 * sites hand-rolled `err instanceof SimConnectorError && err.code === ...`,
 * which is two copies of a rule that must not disagree (§11.1, motif 2).
 */
export function isAuthFailure(err: unknown): boolean {
  return err instanceof SimConnectorError && err.code === 'AUTH_FAILED';
}

// ============================================================================
// Credentials (decrypted — in memory, for the duration of one sweep)
// ============================================================================

export type SimCredential =
  | { authMode: 'password'; username: string; password: string }
  | { authMode: 'token'; token: string };

/** Every literal a connector must keep out of its own error messages. */
export function credentialSecrets(cred: SimCredential | null): string[] {
  if (!cred) return [];
  return cred.authMode === 'password' ? [cred.password, cred.username] : [cred.token];
}

// ============================================================================
// What a connector returns
// ============================================================================

export interface RawSimLine {
  msisdn: string;
  /** Null when the partner did not report one. NEVER ''. */
  operator: string | null;
  clientCode: string | null;
  /** Null on every partner read today — see `SimLine.iccid`. */
  iccid: string | null;
  status: SimLineStatus;
}

export interface RawSimBalance {
  /** Never ''. A connector that cannot read a zone label uses `UNKNOWN_ZONE`. */
  zone: string;
  rechargeMb: number | null;
  usedMb: number | null;
  /** THE value the whole feature turns on. `null` = not answered, never 0. */
  restMb: number | null;
}

// ============================================================================
// Session
// ============================================================================

export interface SimConnectorContext {
  accountId: number;
  /** Null = the connector's own default host. */
  baseUrl: string | null;
  partnerRef: string | null;
  authMode: SimAuthMode;
  credential: SimCredential;
  timeoutMs?: number;
}

/**
 * What a listing call actually returned, and whether it was all of it.
 *
 * ┌─ THE ENDPOINT IS CALLED `...Paged` AND THE CONNECTOR READS PAGE ONE ─────┐
 * │ `GetLigneGsmByFilterPaged` takes no page, no size and no cursor in the   │
 * │ form the extranet's bundle revealed, and the connector sends none. Above │
 * │ whatever the partner's page size turns out to be, the remainder is       │
 * │ SILENTLY absent: never inserted, never balance-read, never alerted on,   │
 * │ never proposed for, never invoiced — and the sweep reports `ok`.         │
 * │                                                                        │
 * │ The failure is silent, permanent, and grows with the customer, which is  │
 * │ the worst combination available. It cannot be FIXED without knowing the  │
 * │ partner's paging parameters, but it can be DETECTED: several of these    │
 * │ APIs return a declared total alongside the page. When the total exceeds  │
 * │ what came back, the sweep says so instead of reporting a smaller fleet.  │
 * │                                                                        │
 * │ `declaredTotal` is `null` when the partner said nothing, which is not    │
 * │ evidence that the page was complete — only that we cannot tell. The      │
 * │ sweep records the distinction.                                           │
 * └────────────────────────────────────────────────────────────────────────┘
 */
export interface SimLineListing {
  lines: RawSimLine[];
  /** The partner's own count of matching lines, when it reports one. */
  declaredTotal: number | null;
}

export interface SimSession {
  /**
   * The partner reference the session actually resolved to — decoded from a
   * token when the account did not carry one. Persisted so the next sweep does
   * not have to decode it again, and so a screen can show which partner account
   * a token really belongs to rather than which one somebody typed.
   */
  readonly partnerRef: string | null;
  /** From the token's own expiry claim when it has one. Null when unknown. */
  readonly tokenExpiresAt: string | null;

  listLines(): Promise<SimLineListing>;
  fetchBalances(msisdn: string): Promise<RawSimBalance[]>;
  close(): Promise<void>;
}

export interface SimConnector {
  readonly platform: SimPlatform;
  readonly ingestion: readonly SimIngestionKind[];
  /**
   * Opens an authenticated session.
   *
   * Throws `SimConnectorError('NOT_IMPLEMENTED')` for a partner ObliWAN cannot
   * read yet. That refusal is deliberate and is surfaced on the account screen:
   * an account configured against an unimplemented partner must look broken,
   * because a fleet of lines nobody is reading must never look watched.
   */
  open(ctx: SimConnectorContext): Promise<SimSession>;
}

// ============================================================================
// Recharge execution — the registry that is empty ON PURPOSE
// ============================================================================

export interface RechargeRequest {
  msisdn: string;
  zone: string;
  planMb: number | null;
}

export interface RechargeOutcome {
  /** The partner's own reference for the purchase, for the billing report. */
  reference: string | null;
  costCents: number | null;
  currency: string | null;
}

export interface SimRechargeAdapter {
  readonly platform: SimPlatform;
  execute(ctx: SimConnectorContext, req: RechargeRequest): Promise<RechargeOutcome>;
}

/**
 * EMPTY, ON PURPOSE. Do not add an entry to make a screen look finished.
 *
 * ┌─ WHY THIS IS A DELIBERATE STATE AND NOT A TODO ───────────────────────────┐
 * │ An entry here is what makes `executed` reachable — the state in which     │
 * │ ObliWAN itself buys data, with nobody in the loop, against a real         │
 * │ account, for real money that no rollback returns. The identical           │
 * │ construction guards on-device peer recovery in                            │
 * │ `safeApply.service.PEER_RECOVERY_ADAPTERS`, for the identical reason:     │
 * │ populating a registry changes what a human is being asked to approve.     │
 * │                                                                          │
 * │ Today it is empty because NO PARTNER TOP-UP ENDPOINT HAS BEEN OBSERVED.   │
 * │ Phenix's API, as reconstructed from its own web client, authenticates,    │
 * │ lists lines and reads consumption — and does not buy. Writing an adapter  │
 * │ against a guessed URL would produce a feature that reports success and    │
 * │ leaves the site dead.                                                     │
 * │                                                                          │
 * │ Everything upstream of this registry is built and works: detection,       │
 * │ proposal, four-eyes approval, caps, audit and the billing report. An      │
 * │ approved top-up is bought on the partner's portal and RECORDED here,      │
 * │ which is a different terminal state precisely so that the day this        │
 * │ registry is populated, the report can still answer "which of these did    │
 * │ the machine buy".                                                         │
 * │                                                                          │
 * │ THE BAR FOR ADDING AN ENTRY: an endpoint confirmed against a real         │
 * │ partner account, an idempotency story that survives a retry (buying the   │
 * │ same top-up twice is the failure this whole design exists to avoid), and  │
 * │ a caps check proven to run BEFORE the call. Until then this stays `{}`    │
 * │ and `SIM_PLATFORM_CATALOG[].rechargeImplemented` stays `false`.           │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export const SIM_RECHARGE_ADAPTERS: Partial<Record<SimPlatform, SimRechargeAdapter>> = {};
