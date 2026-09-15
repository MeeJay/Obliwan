/**
 * ObliWAN F9 — Phenix Partner connector.
 *
 * ┌─ WHERE THESE ENDPOINTS COME FROM, AND WHY THAT MATTERS ───────────────────┐
 * │ Phenix publishes no partner API documentation. The four calls below were  │
 * │ RECONSTRUCTED FROM THE ANGULAR BUNDLE of its extranet, and a field        │
 * │ prototype exercised them against a real account:                          │
 * │                                                                          │
 * │   POST /Auth/authenticate                      {username,password}        │
 * │   POST /Auth/authenticateWithCodeConfirmation  {username,password,code}   │
 * │   GET  /GsmApi/GetLigneGsmByFilterPaged        ?partenaireId=...          │
 * │   POST /GsmApi/GetSdtrConso                    ?partenaireId&msisdn, []   │
 * │                                                                          │
 * │ THE FIELD NAMES INSIDE THE RESPONSES ARE NOT CONFIRMED. `restValueGo`,    │
 * │ `usedValueGo`, `libelleZoneText` and the rest were read off the front-end │
 * │ that consumes them, not off a response anybody captured. Everything in    │
 * │ this file is therefore written to survive being wrong about a name:       │
 * │ `pickNumber` tries the known spellings and returns `null` when none       │
 * │ matches, and `null` becomes `unknown`, which never triggers a purchase.   │
 * │                                                                          │
 * │ The failure mode being designed out is specific and was live in the       │
 * │ prototype: `(float) ($row['restValueGo'] ?? 0)` turns a renamed field     │
 * │ into "0 Go left" ON EVERY LINE AT ONCE — a fleet-wide, perfectly          │
 * │ plausible, entirely false emergency.                                      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE OTP PROBLEM, WHICH IS A PRODUCT PROBLEM AND NOT A BUG ───────────────┐
 * │ A Phenix account may require a one-time code. `authenticate` then fails   │
 * │ and the only way through is `authenticateWithCodeConfirmation`, which     │
 * │ needs a code from a human — and a sweep that runs at 04:00 has no human.  │
 * │                                                                          │
 * │ So `password` mode is supported and honestly labelled as working only for │
 * │ accounts without OTP, and `token` mode is the mode that survives: an      │
 * │ operator authenticates once (in a browser, or through the OTP endpoint    │
 * │ this connector exposes) and stores the bearer token in the vault. The     │
 * │ token's own `exp` claim is read and persisted so the account screen can   │
 * │ warn BEFORE it dies — because an expired token presents exactly like a    │
 * │ healthy fleet with no news.                                               │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * §8.2 — the username, password and token are passed to `RestTransport` as
 * `secrets` and to `SimConnectorError` as `secrets`, so neither a partner error
 * body nor a network failure can carry them into a log or into
 * `sim_sync_runs.error`. Nothing in this file logs a URL: the MSISDN is in the
 * query string and is customer data.
 */

import {
  UNKNOWN_ZONE,
  gbToMb,
  type SimIngestionKind,
  type SimLineStatus,
} from '@obliwan/shared';
import { RestTransport } from '../transport/rest.transport';
import { DriverError } from '../drivers/types';
import {
  SimConnectorError,
  credentialSecrets,
  type RawSimBalance,
  type RawSimLine,
  type SimConnector,
  type SimConnectorContext,
  type SimLineListing,
  type SimSession,
} from './types';

const PLATFORM = 'phenix' as const;

/** The host the extranet's own bundle targets. Overridable per account. */
export const PHENIX_DEFAULT_BASE_URL = 'https://phenix-mb-api.netcom-group.fr';

/**
 * Response envelopes seen in the wild for this API, in the order the prototype
 * tried them. A payload matching NONE of these is `UNREADABLE` — deliberately
 * not "zero lines". An empty fleet and an unparseable answer look identical on
 * a dashboard, and only one of them means the sweep should stop.
 */
const LIST_KEYS = ['items', 'data', 'result', 'results', 'value', 'lignes'] as const;

// ============================================================================
// Defensive field access
// ============================================================================

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** First present key among the candidates. Absent is `undefined`, never ''. */
function pick(row: Record<string, unknown>, keys: readonly string[]): unknown {
  for (const k of keys) {
    if (Object.prototype.hasOwnProperty.call(row, k)) return row[k];
  }
  return undefined;
}

/**
 * A trimmed string, or `null`.
 *
 * `''` collapses to `null` on purpose: an operator field the partner returned
 * empty is an operator we do not know, and storing `''` would make it match a
 * `skip_operators` entry of `''` and silently stop polling the line.
 */
function pickString(row: Record<string, unknown>, keys: readonly string[]): string | null {
  const v = pick(row, keys);
  if (v === null || v === undefined) return null;
  if (typeof v === 'number') return String(v);
  if (typeof v !== 'string') return null;
  const t = v.trim();
  return t === '' ? null : t;
}

/**
 * A quantity in gigabytes → integer MB, or `null` WHEN ANY DOUBT EXISTS.
 *
 * This is the single most consequential function in the file. Returning 0 for
 * a field that is missing, null, empty, non-numeric or negative would announce
 * an exhausted line; returning `null` announces that we do not know, which is
 * what is actually true. There is no fallback value and there must never be.
 */
function pickGb(row: Record<string, unknown>, keys: readonly string[]): number | null {
  const v = pick(row, keys);
  if (typeof v === 'number' || typeof v === 'string') return gbToMb(v);
  return null;
}

/**
 * Rows out of an envelope, or a refusal.
 *
 * The prototype's last resort was `return [$res]` — treat the envelope itself
 * as one row. That turns an error object into a line with no MSISDN and, worse,
 * turns an unrecognised shape into a plausible-looking result. Here an
 * unrecognised shape throws, which the sweep records as a failed run against
 * the account instead of as a fleet that shrank.
 */
function rowsFrom(payload: unknown, what: string): Record<string, unknown>[] {
  if (Array.isArray(payload)) return payload.filter(isRecord);
  if (isRecord(payload)) {
    for (const k of LIST_KEYS) {
      const v = payload[k];
      if (Array.isArray(v)) return v.filter(isRecord);
      // A single-object envelope is legitimate for a one-element page — but
      // ONLY if the object actually looks like a row. `{data: {}}` or
      // `{result: {error: ...}}` would otherwise become one unusable row,
      // which `listLines` then skips for want of an MSISDN: an unreadable
      // answer silently rendered as an EMPTY FLEET, which is the one thing
      // this function's own header says it refuses to do.
      if (isRecord(v) && Object.keys(v).length > 0) return [v];
    }
  }
  throw new SimConnectorError(
    `Phenix ${what}: unrecognised response envelope. The API answered something ` +
      `that is neither a list nor a known wrapper (${LIST_KEYS.join(', ')}), so the ` +
      `result cannot be read. Reporting this as an error rather than as an empty ` +
      `fleet is deliberate.`,
    'UNREADABLE',
    PLATFORM,
  );
}

/**
 * The partner's declared total for a paged listing, when it reports one.
 *
 * Best effort over the spellings these .NET APIs use. `null` means the partner
 * said nothing — which is NOT evidence that the page was complete, and the
 * sweep records that difference rather than assuming the happier reading.
 */
const TOTAL_KEYS = [
  'totalCount', 'TotalCount', 'total', 'Total',
  'totalRecords', 'totalItems', 'recordsTotal', 'nbTotal', 'count',
] as const;

function totalFrom(payload: unknown): number | null {
  if (!isRecord(payload)) return null;
  for (const k of TOTAL_KEYS) {
    const v = payload[k];
    if (typeof v === 'number' && Number.isInteger(v) && v >= 0) return v;
    if (typeof v === 'string' && /^[0-9]+$/.test(v.trim())) return Number(v.trim());
  }
  return null;
}

// ============================================================================
// JWT (best effort — a claim we cannot read is a claim we do not use)
// ============================================================================

function b64urlDecode(part: string): string | null {
  try {
    const s = part.replace(/-/g, '+').replace(/_/g, '/');
    const pad = s.length % 4 === 0 ? s : s + '='.repeat(4 - (s.length % 4));
    return Buffer.from(pad, 'base64').toString('utf8');
  } catch {
    return null;
  }
}

function jwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length < 2) return null;
  const json = b64urlDecode(parts[1]);
  if (!json) return null;
  try {
    const parsed: unknown = JSON.parse(json);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * The partner id the token was issued for.
 *
 * Read from the TOKEN rather than trusted from the account row when both exist:
 * a token minted for partner A cannot list partner B's lines, and silently
 * querying with a mismatched id returns an empty page that reads as "this
 * customer has no SIMs".
 */
export function partnerRefFromJwt(token: string): string | null {
  const payload = jwtPayload(token);
  if (!payload) return null;
  for (const k of ['PartenaireId', 'partenaireId', 'partner_id', 'PartnerId']) {
    const v = payload[k];
    if (typeof v === 'number' && Number.isFinite(v)) return String(v);
    if (typeof v === 'string' && /^[0-9]+$/.test(v.trim())) return v.trim();
  }
  return null;
}

/** `exp` is seconds since the epoch. Null when the token does not carry one. */
export function expiryFromJwt(token: string): string | null {
  const payload = jwtPayload(token);
  const exp = payload?.exp;
  if (typeof exp !== 'number' || !Number.isFinite(exp)) return null;
  return new Date(exp * 1000).toISOString();
}

// ============================================================================
// Session
// ============================================================================

class PhenixSession implements SimSession {
  constructor(
    private readonly rest: RestTransport,
    private readonly token: string,
    readonly partnerRef: string | null,
    readonly tokenExpiresAt: string | null,
    private readonly secrets: string[],
  ) {}

  /**
   * The bearer header, applied to EVERY authenticated request.
   *
   * This getter existed with no caller in the first draft, so both reads went
   * out with no `Authorization` at all and the partner answered 401 on every
   * line — §11.1 motif 2, "a function states a rule and has no caller", caught
   * by `fakePhenixApi` on the first run of `f9-rules.verify.ts`. Both call
   * sites below spread it, and the harness asserts the fake actually SAW a
   * token (`fake.tokensSeen`), so removing it again fails the verification
   * rather than failing silently against a real account.
   */
  private get authHeaders(): Record<string, string> {
    return { Authorization: `Bearer ${this.token}` };
  }

  /**
   * Every session read goes through here, and nothing calls `this.rest.request`
   * directly. See the block in `listLines`: the transport throws on 429 and 5xx
   * instead of returning, so a bare call leaks the request path — MSISDN and
   * all — into the log and into `sim_sync_runs.error`.
   */
  private async request<T>(
    method: 'GET' | 'POST',
    path: string,
    opts: Parameters<RestTransport['request']>[2],
  ): Promise<{ statusCode: number; body: T }> {
    try {
      return await this.rest.request<T>(method, path, opts);
    } catch (err) {
      throw asSimError(err, this.secrets);
    }
  }

  /**
   * Maps a partner HTTP status onto the vocabulary the sweep reasons with.
   *
   * 401/403 is `AUTH_FAILED`, which stops the whole account: continuing would
   * produce one identical failure per line, a `lines_failed` count equal to the
   * fleet size, and an account that looks flaky rather than logged out.
   */
  private fail(status: number, body: string, what: string): never {
    if (status === 401 || status === 403) {
      throw new SimConnectorError(
        `Phenix ${what}: HTTP ${status}. The token is expired, revoked, or the account ` +
          `lacks the partner role. Re-supply a token on the account screen.`,
        'AUTH_FAILED',
        PLATFORM,
        { statusCode: status, secrets: this.secrets },
      );
    }
    throw new SimConnectorError(
      // `stripQuery` on the partner's own body too: a 400 from this API has
      // been known to echo the submitted request line back.
      stripQuery(`Phenix ${what}: HTTP ${status} ${body.slice(0, 200)}`),
      'PARTNER_ERROR',
      PLATFORM,
      { statusCode: status, secrets: this.secrets },
    );
  }

  async listLines(): Promise<SimLineListing> {
    if (!this.partnerRef) {
      throw new SimConnectorError(
        'Phenix listLines: no partner id. Set it on the account, or supply a token ' +
          'whose claims carry one — querying without it returns an empty page, which ' +
          'is indistinguishable from a partner with no lines.',
        'CONFIG_ERROR',
        PLATFORM,
      );
    }
    // Every parameter goes through URLSearchParams. The partner id is opaque
    // partner data and the filters are empty strings today, but an unescaped
    // value here is a query-string injection into somebody else's API
    // (§11.1, motif 6).
    const qs = new URLSearchParams({
      partenaireId: this.partnerRef,
      partenaireIdFor: this.partnerRef,
      partenaireFilterId: this.partnerRef,
      codeClient: '',
      msisdn: '',
    });

    // ┌─ WRAPPED, BECAUSE 429 AND 5xx NEVER REACH THE STATUS CHECK BELOW ────┐
    // │ `RestTransport.request` THROWS on 429 and 5xx rather than returning   │
    // │ a response, so `res.statusCode >= 400` — and therefore `this.fail()`, │
    // │ the only place `stripQuery` was applied to a read — was simply never  │
    // │ reached for those. The raw `DriverError` escaped with the full path,  │
    // │ query string included, straight into `logger.warn` and                │
    // │ `sim_sync_runs.error`: one customer MSISDN per rate-limited line, per │
    // │ sweep. `asSimError` applies both the query strip and the credential   │
    // │ scrub, so both reads go through it.                                    │
    // └──────────────────────────────────────────────────────────────────────┘
    const res = await this.request<unknown>(
      'GET',
      `/GsmApi/GetLigneGsmByFilterPaged?${qs.toString()}`,
      { headers: this.authHeaders, expect: 'json' },
    );
    if (res.statusCode >= 400) {
      this.fail(res.statusCode, typeof res.body === 'string' ? res.body : '', 'listLines');
    }

    const rows = rowsFrom(res.body, 'listLines');
    const declaredTotal = totalFrom(res.body);
    const out: RawSimLine[] = [];
    for (const r of rows) {
      const msisdn = pickString(r, ['msisdn', 'Msisdn', 'numero', 'numeroLigne', 'NumeroLigne']);
      // A row with no number is not a line we can ask about. Skipped rather
      // than stored with a placeholder: a placeholder MSISDN would violate the
      // CHECK on `sim_lines.msisdn` and abort the whole sweep at that row.
      if (!msisdn) continue;
      out.push({
        msisdn,
        operator: pickString(r, ['operateur', 'Operateur', 'operator', 'Operator']),
        clientCode: pickString(r, ['codeClient', 'CodeClient', 'code_client']),
        // Not returned by this endpoint. Declared explicitly so the absence is
        // a decision in the code rather than an omission — see `SimLine.iccid`.
        iccid: null,
        status: readStatus(r),
      });
    }
    return { lines: out, declaredTotal };
  }

  async fetchBalances(msisdn: string): Promise<RawSimBalance[]> {
    if (!this.partnerRef) {
      throw new SimConnectorError(
        'Phenix fetchBalances: no partner id resolved for this account.',
        'CONFIG_ERROR',
        PLATFORM,
      );
    }
    const qs = new URLSearchParams({ partenaireId: this.partnerRef, msisdn });

    // The extranet POSTs an empty consumption list and reads the zones back.
    // `idempotent: false` is not a formality: this is a POST, and
    // `RestTransport` would otherwise replay it on a 429 or a 502.
    const res = await this.request<unknown>(
      'POST',
      `/GsmApi/GetSdtrConso?${qs.toString()}`,
      { headers: this.authHeaders, body: [], expect: 'json', idempotent: false },
    );
    if (res.statusCode >= 400) {
      this.fail(res.statusCode, typeof res.body === 'string' ? res.body : '', 'fetchBalances');
    }

    const rows = rowsFrom(res.body, 'fetchBalances');
    return rows.map((r) => ({
      zone:
        pickString(r, ['libelleZoneText', 'libelleZone', 'zone', 'Zone', 'zoneLabel']) ??
        UNKNOWN_ZONE,
      rechargeMb: pickGb(r, ['rechargeGo', 'RechargeGo', 'rechargeValueGo']),
      usedMb: pickGb(r, ['usedValueGo', 'UsedValueGo', 'consoGo', 'ConsoGo']),
      restMb: pickGb(r, ['restValueGo', 'RestValueGo', 'resteGo', 'ResteGo']),
    }));
  }

  async close(): Promise<void> {
    await this.rest.close();
  }
}

/**
 * A line's state, when the partner says anything about it.
 *
 * Defaults to `unknown` rather than `active`: an inactive line reported as
 * active is a line whose zero balance is treated as an emergency for months.
 */
function readStatus(row: Record<string, unknown>): SimLineStatus {
  const raw = pickString(row, ['statut', 'Statut', 'status', 'Status', 'etat', 'Etat']);
  if (!raw) return 'unknown';
  const v = raw.toLowerCase();
  if (/(actif|active|enabled|en service)/.test(v)) return 'active';
  if (/(suspend|resili|inactif|inactive|disabled|bloqu)/.test(v)) return 'suspended';
  return 'unknown';
}

// ============================================================================
// Connector
// ============================================================================

class PhenixConnector implements SimConnector {
  readonly platform = PLATFORM;
  readonly ingestion: readonly SimIngestionKind[] = ['pull'];

  async open(ctx: SimConnectorContext): Promise<SimSession> {
    const secrets = credentialSecrets(ctx.credential);
    const rest = new RestTransport({
      baseUrl: ctx.baseUrl ?? PHENIX_DEFAULT_BASE_URL,
      timeoutMs: ctx.timeoutMs ?? 30_000,
      retries: 2,
      // Public CA-signed host: verification on, nothing pinned. This is NOT the
      // on-box appliance case `rest.transport` pins for.
      tls: { rejectUnauthorized: true },
      secrets,
    });

    try {
      const token =
        ctx.credential.authMode === 'token'
          ? ctx.credential.token
          : await authenticateWithPassword(rest, ctx.credential.username, ctx.credential.password, secrets);

      // ┌─ THE OBTAINED TOKEN IS A SECRET TOO ────────────────────────────────┐
      // │ In `token` mode it is already in `secrets` (it IS the credential).  │
      // │ In `password` mode the first draft's `secrets` held only the        │
      // │ username and password, so the bearer token minted by                │
      // │ `/Auth/authenticate` — which grants the same access — was NOT       │
      // │ scrubbed from any later error, and this file's own §8.2 header was  │
      // │ therefore false for exactly one of its two modes. Added here rather │
      // │ than at each throw site, for the same reason `SimConnectorError`    │
      // │ scrubs in its constructor: a rule nobody can forget.                │
      // └────────────────────────────────────────────────────────────────────┘
      const sessionSecrets = secrets.includes(token) ? secrets : [...secrets, token];

      // The token's own claim wins over the stored partner id when it has one.
      const partnerRef = partnerRefFromJwt(token) ?? ctx.partnerRef;
      return new PhenixSession(rest, token, partnerRef, expiryFromJwt(token), sessionSecrets);
    } catch (err) {
      // The session never took ownership of the pool, so close it here or the
      // undici agent leaks one socket set per failed sweep — on a broken
      // account that is one leak every four hours, forever.
      await rest.close().catch(() => undefined);
      throw asSimError(err, secrets);
    }
  }
}

async function authenticateWithPassword(
  rest: RestTransport,
  username: string,
  password: string,
  secrets: string[],
): Promise<string> {
  const res = await rest.request<unknown>('POST', '/Auth/authenticate', {
    body: { username, password },
    expect: 'json',
    idempotent: false,
  });

  if (res.statusCode === 401 || res.statusCode === 403) {
    throw new SimConnectorError(
      `Phenix authenticate: HTTP ${res.statusCode}. Either the credentials are wrong, ` +
        `or this account requires a one-time code — password mode cannot complete that ` +
        `flow unattended. Switch the account to token mode.`,
      'AUTH_FAILED',
      PLATFORM,
      { statusCode: res.statusCode, secrets },
    );
  }
  if (res.statusCode >= 400) {
    throw new SimConnectorError(
      `Phenix authenticate: HTTP ${res.statusCode}`,
      'PARTNER_ERROR',
      PLATFORM,
      { statusCode: res.statusCode, secrets },
    );
  }

  const body = res.body;
  const token = isRecord(body)
    ? ((body.access_token ?? body.accessToken ?? body.token) as unknown)
    : null;
  if (typeof token !== 'string' || token.trim() === '') {
    throw new SimConnectorError(
      'Phenix authenticate: the response carried no access token. This is also what a ' +
        'one-time-code challenge looks like from here.',
      'AUTH_FAILED',
      PLATFORM,
      { secrets },
    );
  }
  return token.trim();
}

/**
 * Authenticates with a one-time code and returns the bearer token.
 *
 * Exported and used by ONE interactive endpoint, never by the sweep — the whole
 * point of the OTP flow is that a human is present. What the caller does with
 * the result is store it as the account's `token` credential, which is the only
 * mode that then runs unattended.
 */
export async function phenixAuthenticateWithCode(
  baseUrl: string | null,
  username: string,
  password: string,
  code: string,
): Promise<{ token: string; partnerRef: string | null; expiresAt: string | null }> {
  const secrets = [password, username, code];
  const rest = new RestTransport({
    baseUrl: baseUrl ?? PHENIX_DEFAULT_BASE_URL,
    timeoutMs: 30_000,
    retries: 0,
    tls: { rejectUnauthorized: true },
    secrets,
  });
  try {
    const res = await rest.request<unknown>('POST', '/Auth/authenticateWithCodeConfirmation', {
      body: { username, password, code },
      expect: 'json',
      idempotent: false,
    });
    if (res.statusCode >= 400) {
      throw new SimConnectorError(
        `Phenix authenticateWithCodeConfirmation: HTTP ${res.statusCode}`,
        res.statusCode === 401 || res.statusCode === 403 ? 'AUTH_FAILED' : 'PARTNER_ERROR',
        PLATFORM,
        { statusCode: res.statusCode, secrets },
      );
    }
    const body = res.body;
    const token = isRecord(body)
      ? ((body.access_token ?? body.accessToken ?? body.token) as unknown)
      : null;
    if (typeof token !== 'string' || token.trim() === '') {
      throw new SimConnectorError(
        'Phenix authenticateWithCodeConfirmation: no access token in the response.',
        'AUTH_FAILED',
        PLATFORM,
        { secrets },
      );
    }
    const t = token.trim();
    return { token: t, partnerRef: partnerRefFromJwt(t), expiresAt: expiryFromJwt(t) };
  } catch (err) {
    throw asSimError(err, secrets);
  } finally {
    await rest.close().catch(() => undefined);
  }
}

/**
 * Removes the query string from anything that looks like a path in a message.
 *
 * ┌─ THE MSISDN TRAVELS IN THE QUERY STRING, AND IT IS CUSTOMER DATA ────────┐
 * │ `RestTransport.httpError` builds its message as `${path} -> HTTP ${n}`,  │
 * │ and this connector's paths are                                           │
 * │ `/GsmApi/GetSdtrConso?partenaireId=4242&msisdn=33600000001`. That        │
 * │ message propagates through `asSimError` into `logger.warn` and into      │
 * │ `sim_sync_runs.error`, which the account screen renders — so a partner   │
 * │ 429 quietly published a subscriber's number into the application log and │
 * │ a database column, two lines below the header that forbids exactly that. │
 * │                                                                         │
 * │ The path is kept (it says WHICH call failed, which is the diagnostic     │
 * │ value); everything after the `?` is replaced.                            │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
export function stripQuery(message: string): string {
  return message.replace(/(\/[A-Za-z0-9_\-./]*)\?[^\s]*/g, '$1?…');
}

/** Transport-level failures become connector-level ones, still scrubbed. */
function asSimError(err: unknown, secrets: string[]): SimConnectorError {
  if (err instanceof SimConnectorError) return err;
  const message = err instanceof Error ? err.message : String(err);
  return new SimConnectorError(stripQuery(message), 'PARTNER_ERROR', PLATFORM, { secrets });
}

export const phenixConnector: SimConnector = new PhenixConnector();
