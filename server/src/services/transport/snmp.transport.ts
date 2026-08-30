/**
 * ObliWAN — the SNMP transport, on `net-snmp`.
 *
 * ┌─ THIS FILE IS THE SINGLE OWNER OF SNMP SESSION LIFECYCLE ─────────────────┐
 * │ One `lru-cache`. One `dispose()` that closes. One error classification.   │
 * │ One place where a session is evicted on timeout. Nothing else in the      │
 * │ server may call `snmp.createSession()`.                                   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * WHY IT IS ONE FILE AND NOT TWO.
 * M2 shipped this transport (identify a box over MIB-II). M3 needed a WALK of
 * the ifTable and the ASN.1 TYPE of every varbind, so it grew a second client,
 * `services/snmp/snmpClient.ts`, with its own `lru-cache`, its own `dispose`,
 * its own retry budget and its own error classes. That is TWO places where a
 * UDP socket can leak, and the leak is the exact failure the cache exists to
 * prevent: `net-snmp` opens one socket per session and releases it only on
 * `session.close()`; at 300 devices a session-per-request exhausts the
 * container's file descriptors within hours and surfaces as an EMFILE on some
 * unrelated HTTP call. The M3 needs were a reason to WIDEN this abstraction,
 * not to clone it. `snmpClient.ts` is gone — deleted, not re-exported from
 * here, because a compatibility shim is how a second implementation grows back.
 *
 * WHAT THE MERGE HAD TO PRESERVE FROM EACH SIDE
 *  - from M2: `SnmpTarget` / `SnmpSessionCache` / `snmpGet` / `snmpIdentify` /
 *    `brandFromSnmp` and their signatures — `drivers/base.ts` and the driver
 *    self-test call them and live in another workstream's tree;
 *  - from M3: the TYPE-AWARE decode. A Counter64 arrives as 8 big-endian bytes
 *    and `Number(buffer)` is `NaN`; decoding it as text does not throw, it
 *    yields mojibake, and every HC interface silently becomes AGENT_ERROR
 *    forever. `walk()`, `getMany()` chunking, and the `asCounter/asInt/asText`
 *    accessors come from that side unchanged.
 *
 * Section 8.2: the cache key carries a HASH of the credential material, never
 * the community string or the USM keys — cache keys end up in metrics and
 * debug logs, and a community string is a credential.
 */

import { createHash } from 'crypto';
import { LRUCache } from 'lru-cache';
import * as snmp from 'net-snmp';
import type {
  SnmpAuthProtocol,
  SnmpPrivProtocol,
  SnmpSecurityLevel,
  SnmpVersion,
} from '@obliwan/shared';
import { DriverError } from '../drivers/types';
import type { SnmpCredentialMaterial } from '../drivers/types';

// ============================================================================
// Target
// ============================================================================

/**
 * Decrypted credential material for one agent.
 *
 * A superset of the driver layer's `SnmpCredentialMaterial`: it adds the
 * EXPLICIT `securityLevel` that `snmp_credentials.security_level` carries, and
 * it accepts the full protocol vocabulary of `@obliwan/shared` (`3des`, which
 * the driver-facing type does not list). Widening rather than replacing is
 * what keeps `drivers/base.ts` compiling untouched — the assertion below fails
 * the build the day the two drift apart.
 */
export interface SnmpCredentials {
  /** v2c community. Never logged, never in a cache key. */
  community?: string | null;
  /** v3 USM user name (not a secret, but it lives with the rest). */
  username?: string | null;
  /**
   * The level the credential row declares. When absent (the driver path, which
   * has no such column) it is DERIVED from which keys are set — see
   * `securityLevelOf()`. Explicit wins: an operator who stored `authNoPriv`
   * while a privKey lingers in the vault must get authNoPriv on the wire.
   */
  securityLevel?: SnmpSecurityLevel | null;
  authProtocol?: SnmpAuthProtocol | null;
  authKey?: string | null;
  privProtocol?: SnmpPrivProtocol | null;
  privKey?: string | null;
  context?: string | null;
}

/**
 * Compile-time proof that a driver's credential material is still a valid
 * `SnmpCredentials`. `drivers/types.ts` belongs to another workstream; if it
 * ever adds a protocol name that `@obliwan/shared` does not know, this line
 * turns `never` and the build stops here instead of at a runtime
 * `Unknown SNMP auth protocol` on a live device.
 */
const _DRIVER_CREDENTIALS_STILL_FIT: SnmpCredentialMaterial extends SnmpCredentials
  ? true
  : never = true;
void _DRIVER_CREDENTIALS_STILL_FIT;

/**
 * Version as a caller may spell it. `@obliwan/shared` says `v1/v2c/v3` (it is
 * what the DB enum stores); the M2 driver layer says `2c/3`. Both are accepted
 * on the way in and normalised to the shared spelling exactly once, in
 * `dialTarget()`.
 */
export type SnmpVersionInput = SnmpVersion | '1' | '2c' | '3';

/** Everything needed to talk to one agent, secrets already decrypted. */
export interface SnmpTarget {
  host: string;
  port?: number;
  version: SnmpVersionInput;
  credentials: SnmpCredentials;
  timeoutMs?: number;
  retries?: number;
  /** GETBULK repetitions used by `walk()`. Ignored on the GET path. */
  maxRepetitions?: number;
}

/** An `SnmpTarget` with every default resolved. What the cache keys, what the
 *  factory receives, and the only shape the wire code reads. */
export interface SnmpDialTarget extends SnmpTarget {
  port: number;
  version: SnmpVersion;
  timeoutMs: number;
  retries: number;
  maxRepetitions: number;
}

const DEFAULT_PORT = 161;
const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_RETRIES = 1;
/** net-snmp's own default is 20. 25 keeps an ifTable column of a 24-port switch
 *  to a single GETBULK round trip without risking a `tooBig` on a tunnel MTU. */
const DEFAULT_MAX_REPETITIONS = 25;

const VERSION_ALIAS: Record<SnmpVersionInput, SnmpVersion> = {
  '1': 'v1',
  v1: 'v1',
  '2c': 'v2c',
  v2c: 'v2c',
  '3': 'v3',
  v3: 'v3',
};

/** Normalise a caller's target. The ONE place defaults and version spellings
 *  are resolved, so the cache key and the session options can never disagree
 *  about what "the same target" means. */
export function dialTarget(target: SnmpTarget): SnmpDialTarget {
  const version = VERSION_ALIAS[target.version];
  if (!version) {
    throw new DriverError(
      `SNMP ${target.host}: unknown version "${String(target.version)}"`,
      'PROTOCOL_ERROR',
      { transport: 'snmp', retryable: false },
    );
  }
  return {
    ...target,
    port: target.port ?? DEFAULT_PORT,
    version,
    timeoutMs: target.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    retries: target.retries ?? DEFAULT_RETRIES,
    maxRepetitions: target.maxRepetitions ?? DEFAULT_MAX_REPETITIONS,
  };
}

/** Standard MIB-II system group. No private MIB here, on purpose: every vendor
 *  branch among the four brands either duplicates MIB-II or is too thin to be
 *  worth making the identifier brand-aware. */
export const SYSTEM_OID = {
  sysDescr: '1.3.6.1.2.1.1.1.0',
  sysObjectID: '1.3.6.1.2.1.1.2.0',
  sysUpTime: '1.3.6.1.2.1.1.3.0',
  sysContact: '1.3.6.1.2.1.1.4.0',
  sysName: '1.3.6.1.2.1.1.5.0',
  sysLocation: '1.3.6.1.2.1.1.6.0',
} as const;

/** IANA enterprise numbers of the four brands, read off `sysObjectID`. */
export const ENTERPRISE_OID = {
  mikrotik: '1.3.6.1.4.1.14988',
  draytek: '1.3.6.1.4.1.7367',
  zyxel: '1.3.6.1.4.1.890',
  sonicwall: '1.3.6.1.4.1.8741',
} as const;

// ============================================================================
// Varbinds and decoding
// ============================================================================

/** ASN.1 tags we branch on. Named so nobody has to remember that 70 is
 *  Counter64 — the tag whose mishandling costs the most. */
export const ASN1 = {
  Integer: 2,
  OctetString: 4,
  Null: 5,
  OID: 6,
  IpAddress: 64,
  Counter32: 65,
  Gauge32: 66,
  TimeTicks: 67,
  Opaque: 68,
  Counter64: 70,
  NoSuchObject: 128,
  NoSuchInstance: 129,
  EndOfMibView: 130,
} as const;

export interface SnmpVarbind {
  oid: string;
  /** The ASN.1 tag the agent answered with. See `ASN1`. */
  type: number;
  /** Integers/gauges as `number`, counters as `bigint`, strings as `string`. */
  value: string | number | bigint | null;
  /** The untouched octets, for anything that is not text (ifPhysAddress). */
  bytes: Buffer | null;
  /** noSuchObject / noSuchInstance / endOfMibView. NOT an error: half a fleet
   *  has no `sysLocation` and a good share has no ifXTable, and treating that
   *  as a failure marks a healthy device unreachable. */
  missing: boolean;
}

/**
 * One `net-snmp` varbind into ours.
 *
 * The three "missing" tags are tested by NUMBER rather than through
 * `snmp.isVarbindError()` — same three values, but a test double does not have
 * to be a real `net-snmp` varbind for the self-tests to mean anything.
 */
export function decodeVarbind(vb: snmp.Varbind): SnmpVarbind {
  const type = Number(vb.type);
  if (type === ASN1.NoSuchObject || type === ASN1.NoSuchInstance || type === ASN1.EndOfMibView) {
    return { oid: vb.oid, type, value: null, bytes: null, missing: true };
  }
  const raw = vb.value;
  if (raw === null || raw === undefined) {
    return { oid: vb.oid, type, value: null, bytes: null, missing: false };
  }

  if (Buffer.isBuffer(raw)) {
    // A Counter64 arrives here as 8 big-endian bytes. Decoding it as text is
    // the single most damaging mistake available in this file: it does not
    // throw, it yields mojibake, `asCounter` returns null, and every HC
    // interface silently becomes AGENT_ERROR forever.
    if (type === ASN1.Counter64) {
      let n = 0n;
      for (const byte of raw) n = (n << 8n) | BigInt(byte);
      return { oid: vb.oid, type, value: n, bytes: raw, missing: false };
    }
    if (type === ASN1.IpAddress && raw.length === 4) {
      return { oid: vb.oid, type, value: Array.from(raw).join('.'), bytes: raw, missing: false };
    }
    return {
      oid: vb.oid,
      type,
      value: raw.toString('utf8').replace(/\0+$/, ''),
      bytes: raw,
      missing: false,
    };
  }

  if (typeof raw === 'bigint') {
    return { oid: vb.oid, type, value: raw, bytes: null, missing: false };
  }
  return { oid: vb.oid, type, value: raw as string | number, bytes: null, missing: false };
}

/**
 * A varbind as an UNSIGNED counter.
 *
 * `null` when the varbind is missing or is not a number — and the caller must
 * treat that as AGENT_ERROR, never as zero. A missing counter read as 0 makes
 * the next poll compute its delta from 0, i.e. one enormous spike.
 */
export function asCounter(vb: SnmpVarbind | undefined): bigint | null {
  if (!vb || vb.missing || vb.value === null) return null;
  if (typeof vb.value === 'bigint') return vb.value >= 0n ? vb.value : null;
  if (typeof vb.value === 'number') {
    if (!Number.isFinite(vb.value)) return null;
    // net-snmp hands Counter32/Gauge32 back as a signed JS number; a value
    // above 2^31 can arrive negative from a sloppy agent. Fold it back into
    // the unsigned range rather than discarding a legitimate reading.
    const n = Math.trunc(vb.value);
    return BigInt(n < 0 ? n + 0x1_0000_0000 : n);
  }
  if (typeof vb.value === 'string' && /^[0-9]+$/.test(vb.value)) return BigInt(vb.value);
  return null;
}

/** A varbind as a plain integer (ifOperStatus, ifType, ifHighSpeed...). */
export function asInt(vb: SnmpVarbind | undefined): number | null {
  if (!vb || vb.missing || vb.value === null) return null;
  const n = Number(vb.value);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

/** A varbind as text. Control bytes are stripped (a vendor ifAlias can carry a
 *  stray CR) and an empty result collapses to null: an agent answering "" for
 *  ifAlias means "no alias", not "the alias is the empty string". */
export function asText(vb: SnmpVarbind | undefined): string | null {
  if (!vb || vb.missing || vb.value === null) return null;
  const s = String(vb.value).replace(/[\u0000-\u001f\u007f]/g, '').trim();
  return s.length > 0 ? s : null;
}

// ============================================================================
// Session cache — the lifecycle owner
// ============================================================================

/**
 * The slice of a `net-snmp` session this module uses. Narrow on purpose: it is
 * what a test double has to implement.
 *
 * `subtree` is OPTIONAL because a double that only exercises the GET path
 * (identification, the M2 driver self-test) has no reason to implement a walk.
 * `snmpWalk()` refuses loudly on a session that lacks it rather than pretending
 * the table is empty — an empty walk is how a discovery mass-vanishes a device.
 */
export interface SnmpSessionLike {
  get(oids: string[], callback: (error: Error | null, varbinds: snmp.Varbind[]) => void): void;
  subtree?(
    oid: string,
    maxRepetitions: number,
    feed: (varbinds: snmp.Varbind[]) => void,
    done: (error: Error | null) => void,
  ): void;
  close(): void;
  on?(event: 'error' | 'close', listener: (error?: Error) => void): unknown;
}

export type SnmpSessionFactory = (target: SnmpDialTarget) => SnmpSessionLike;

export interface SnmpSessionCacheOptions {
  factory: SnmpSessionFactory;
  /** Concurrent live UDP sockets. */
  max?: number;
  /** Idle time after which a session is closed and its socket released. */
  ttlMs?: number;
  /** Called after a session is closed, with the `lru-cache` reason
   *  (`evict` / `expire` / `delete` / `set`). Wiring point for a metric, and
   *  what the self-test reads to tell the three eviction paths apart. */
  onDispose?: (key: string, reason: string) => void;
}

/** 512 concurrent sockets covers a 300-device fleet plus its discoveries with
 *  room to spare; past that, evicting is the correct answer, not growing. */
const SESSION_CACHE_MAX = 512;
/** A device in adaptive back-off is asked again in up to 15 minutes. A 5-minute
 *  idle TTL means its socket is returned in the meantime instead of being held
 *  for a device nobody is talking to. */
const SESSION_TTL_MS = 5 * 60_000;

export class SnmpSessionCache {
  private readonly cache: LRUCache<string, SnmpSessionLike>;
  private readonly factory: SnmpSessionFactory;

  constructor(opts: SnmpSessionCacheOptions) {
    this.factory = opts.factory;
    this.cache = new LRUCache<string, SnmpSessionLike>({
      max: opts.max ?? SESSION_CACHE_MAX,
      ttl: opts.ttlMs ?? SESSION_TTL_MS,
      // Without autopurge, an idle session is only closed when something else
      // touches the cache — i.e. never, on a quiet fleet, and the socket stays.
      ttlAutopurge: true,
      updateAgeOnGet: true,
      dispose: (session, key, reason) => {
        try {
          session.close();
        } catch {
          // A session that is already dead still has to leave the cache.
        }
        opts.onDispose?.(key, String(reason));
      },
    });
  }

  /** Stable, credential-free identity of a session. */
  static keyFor(target: SnmpTarget): string {
    const t = dialTarget(target);
    const c = t.credentials;
    // NUL-joined: without a separator that cannot appear in a credential,
    // ("ab", "c") and ("a", "bc") fingerprint identically.
    const material = [
      c.community ?? '',
      c.username ?? '',
      c.authProtocol ?? '',
      c.authKey ?? '',
      c.privProtocol ?? '',
      c.privKey ?? '',
    ].join('\u0000');
    const fingerprint = createHash('sha256').update(material).digest('hex').slice(0, 16);
    // `securityLevel` is part of the identity, not of the fingerprint: it is
    // not a secret, and two credentials that differ only by it are two
    // different sessions on the wire.
    return [t.host, t.port, t.version, c.context ?? '', c.securityLevel ?? '', fingerprint].join(
      '|',
    );
  }

  acquire(target: SnmpTarget): SnmpSessionLike {
    const key = SnmpSessionCache.keyFor(target);
    const existing = this.cache.get(key);
    if (existing) return existing;
    const session = this.factory(dialTarget(target));
    // A `net-snmp` session that emits 'error' with no listener takes the whole
    // process down. Attached HERE rather than in the factory so the rule holds
    // for every factory, including the ones a bench supplies. The per-request
    // promises carry the real error anyway.
    session.on?.('error', () => undefined);
    this.cache.set(key, session);
    return session;
  }

  /** Drop a session immediately — used when a request errors out or times out,
   *  because a `net-snmp` session whose socket misbehaved may be dead. The
   *  `dispose` hook closes it on the way out. */
  drop(target: SnmpTarget): void {
    this.cache.delete(SnmpSessionCache.keyFor(target));
  }

  get size(): number {
    return this.cache.size;
  }

  /** Close every session. Called on shutdown and on losing leadership. */
  closeAll(): void {
    this.cache.clear();
  }
}

function realSessionFactory(target: SnmpDialTarget): SnmpSessionLike {
  const c = target.credentials;
  const options: snmp.SessionOptions = {
    port: target.port,
    timeout: target.timeoutMs,
    retries: target.retries,
    version:
      target.version === 'v3'
        ? snmp.Version3
        : target.version === 'v1'
          ? snmp.Version1
          : snmp.Version2c,
    ...(c.context ? { context: c.context } : {}),
  };

  if (target.version !== 'v3') {
    if (!c.community) {
      throw new DriverError(
        `SNMP ${target.version} target ${target.host} has no community configured`,
        'AUTH_FAILED',
        { transport: 'snmp', retryable: false },
      );
    }
    return snmp.createSession(target.host, c.community, options);
  }

  if (!c.username) {
    throw new DriverError(
      `SNMP v3 target ${target.host} has no USM user configured`,
      'AUTH_FAILED',
      { transport: 'snmp', retryable: false },
    );
  }
  const user: snmp.V3User = {
    name: c.username,
    level: securityLevelOf(c),
    ...(c.authKey ? { authProtocol: authProtocol(c.authProtocol), authKey: c.authKey } : {}),
    ...(c.privKey ? { privProtocol: privProtocol(c.privProtocol), privKey: c.privKey } : {}),
  };
  return snmp.createV3Session(target.host, user, options);
}

/**
 * noAuthNoPriv / authNoPriv / authPriv.
 *
 * The stored level wins when there is one (`snmp_credentials.security_level`).
 * The driver layer has no such column, so for it the level is derived from
 * which keys are actually set — which is what M2 always did.
 */
export function securityLevelOf(c: SnmpCredentials): number {
  if (c.securityLevel === 'authPriv') return snmp.SecurityLevel.authPriv;
  if (c.securityLevel === 'authNoPriv') return snmp.SecurityLevel.authNoPriv;
  if (c.securityLevel === 'noAuthNoPriv') return snmp.SecurityLevel.noAuthNoPriv;
  if (c.authKey && c.privKey) return snmp.SecurityLevel.authPriv;
  if (c.authKey) return snmp.SecurityLevel.authNoPriv;
  return snmp.SecurityLevel.noAuthNoPriv;
}

/**
 * SHA-2 by default (the spec asks for SHA-2 and AES). MD5 and DES remain
 * reachable only for a device that offers nothing else, and they are named
 * explicitly in the credential rather than reached by accident.
 */
function authProtocol(name: SnmpAuthProtocol | null | undefined): string {
  const map: Record<string, string | undefined> = {
    md5: snmp.AuthProtocols.md5,
    sha: snmp.AuthProtocols.sha,
    sha224: snmp.AuthProtocols.sha224,
    sha256: snmp.AuthProtocols.sha256,
    sha384: snmp.AuthProtocols.sha384,
    sha512: snmp.AuthProtocols.sha512,
  };
  const resolved = name ? map[name] : undefined;
  if (name && !resolved) {
    throw new DriverError(`Unknown SNMP auth protocol "${name}"`, 'PROTOCOL_ERROR', {
      transport: 'snmp',
      retryable: false,
    });
  }
  return resolved ?? snmp.AuthProtocols.sha256 ?? snmp.AuthProtocols.sha;
}

function privProtocol(name: SnmpPrivProtocol | null | undefined): string {
  const map: Record<string, string | undefined> = {
    des: snmp.PrivProtocols.des,
    '3des': snmp.PrivProtocols.des3 ?? snmp.PrivProtocols.des,
    aes: snmp.PrivProtocols.aes,
    aes128: snmp.PrivProtocols.aes,
    aes192: snmp.PrivProtocols.aes192 ?? snmp.PrivProtocols.aes,
    aes256: snmp.PrivProtocols.aes256b ?? snmp.PrivProtocols.aes256r ?? snmp.PrivProtocols.aes,
  };
  const resolved = name ? map[name] : undefined;
  if (name && !resolved) {
    throw new DriverError(`Unknown SNMP privacy protocol "${name}"`, 'PROTOCOL_ERROR', {
      transport: 'snmp',
      retryable: false,
    });
  }
  return resolved ?? snmp.PrivProtocols.aes;
}

/** The process-wide cache. ONE socket budget for the whole server. */
export const snmpSessions = new SnmpSessionCache({ factory: realSessionFactory });

// ============================================================================
// Requests — one budget, one classification, one eviction point
// ============================================================================

/**
 * Ceiling on ANY single operation.
 *
 * Not redundant with `net-snmp`'s own timeout: its callback is driven by its
 * socket, and a socket that never errors and never receives leaves the promise
 * pending forever. A poll that hangs without rejecting never frees its
 * scheduler slot — worse than one that fails.
 */
function budgetMs(target: SnmpDialTarget): number {
  return target.timeoutMs * (target.retries + 1) + 1_000;
}

/** A walk issues several PDUs, so it gets the per-PDU budget times a generous
 *  cap on how many an ifTable column can need. */
const WALK_BUDGET_FACTOR = 8;

/**
 * `net-snmp` reports an authentication/engine mismatch as a plain `Error`, and
 * the distinction matters: a wrong community must not open the breaker, it must
 * surface as a credential problem for a human. `DriverError` derives
 * `retryable` from the code, so this function IS the retry policy.
 */
export function classifySnmpError(err: unknown, host: string): DriverError {
  if (err instanceof DriverError) return err;
  const message = err instanceof Error ? err.message : String(err);
  const code = /RequestTimedOut|Timeout/i.test(message)
    ? 'TIMEOUT'
    : /Authentication|authoritative|UnknownUserName|WrongDigest|DecryptionError|community/i.test(
          message,
        )
      ? 'AUTH_FAILED'
      : /EHOSTUNREACH|ENETUNREACH|ECONNREFUSED|EACCES/i.test(message)
        ? 'UNREACHABLE'
        : 'PROTOCOL_ERROR';
  return new DriverError(`SNMP ${host}: ${message}`, code, { transport: 'snmp', cause: err });
}

/**
 * Runs one callback-style session operation under the hard timer, and makes
 * sure a failed session leaves the cache EXACTLY ONCE.
 *
 * Every SNMP request in the server goes through here. That is the whole point:
 * the timeout budget, the "drop the session on failure" rule and the error
 * classification exist in one place and cannot drift apart.
 */
function request<T>(
  target: SnmpTarget,
  cache: SnmpSessionCache,
  budgetFactor: number,
  timeoutMessage: (t: SnmpDialTarget) => string,
  run: (
    session: SnmpSessionLike,
    settle: (err: unknown, value?: T) => void,
    t: SnmpDialTarget,
  ) => void,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    // Normalising and acquiring happen INSIDE the promise so that a malformed
    // target rejects like every other SNMP failure. An async-looking function
    // that sometimes throws synchronously is how a poll escapes its own
    // try/catch and takes a scheduler tick with it.
    let t: SnmpDialTarget;
    let session: SnmpSessionLike;
    try {
      t = dialTarget(target);
      session = cache.acquire(t);
    } catch (err) {
      reject(classifySnmpError(err, target.host));
      return;
    }

    let settled = false;
    const fail = (err: unknown): void => {
      settled = true;
      // The socket may be unusable; do not hand it to the next caller. THIS is
      // the single eviction point on failure, for GET and WALK alike.
      cache.drop(t);
      reject(classifySnmpError(err, t.host));
    };

    const timer = setTimeout(() => {
      if (settled) return;
      fail(new DriverError(timeoutMessage(t), 'TIMEOUT', { transport: 'snmp' }));
    }, budgetMs(t) * budgetFactor);

    const settle = (err: unknown, value?: T): void => {
      if (settled) return;
      clearTimeout(timer);
      if (err) {
        fail(err);
        return;
      }
      settled = true;
      resolve(value as T);
    };

    try {
      run(session, settle, t);
    } catch (err) {
      settle(err);
    }
  });
}

/**
 * One GET. Resolves with one varbind per requested OID, in the order asked.
 */
export function snmpGet(
  target: SnmpTarget,
  oids: string[],
  cache: SnmpSessionCache = snmpSessions,
): Promise<SnmpVarbind[]> {
  if (oids.length === 0) return Promise.resolve([]);
  return request<SnmpVarbind[]>(
    target,
    cache,
    1,
    (x) => `SNMP ${x.host}: no answer within ${budgetMs(x)} ms`,
    (session, settle) => {
      session.get(oids, (error, varbinds) => {
        settle(error, (varbinds ?? []).map(decodeVarbind));
      });
    },
  );
}

/**
 * Full walk of one column, varbinds in OID order.
 *
 * Rows outside the subtree are dropped: `subtree` stops by itself, but an agent
 * that overruns its own table would otherwise inject another column's values
 * into the discovery — which is how the WAN octets end up on the LAN graph.
 */
export function snmpWalk(
  target: SnmpTarget,
  baseOid: string,
  cache: SnmpSessionCache = snmpSessions,
): Promise<SnmpVarbind[]> {
  return request<SnmpVarbind[]>(
    target,
    cache,
    WALK_BUDGET_FACTOR,
    (x) => `SNMP ${x.host}: walk of ${baseOid} timed out`,
    (session, settle, t) => {
      if (typeof session.subtree !== 'function') {
        // Loud on purpose. Returning [] here would read as "this device has no
        // interfaces", and discovery would vanish every one of them.
        settle(
          new DriverError(
            `SNMP ${t.host}: this session cannot walk (no subtree())`,
            'PROTOCOL_ERROR',
            { transport: 'snmp', retryable: false },
          ),
        );
        return;
      }
      const out: SnmpVarbind[] = [];
      session.subtree(
        baseOid,
        t.maxRepetitions,
        (varbinds) => {
          for (const vb of varbinds) {
            const d = decodeVarbind(vb);
            if (d.oid.startsWith(`${baseOid}.`)) out.push(d);
          }
        },
        (error) => settle(error, out),
      );
    },
  );
}

// ============================================================================
// The connection façade — what the M3 poller and discovery hold
// ============================================================================

/**
 * A target bound to the cache, as an object.
 *
 * It owns NO socket: every call goes back through the single cache, so a
 * connection handed around for the length of a poll cycle cannot outlive (or
 * hide) the session underneath it.
 */
export interface SnmpConnection {
  get(oids: string[]): Promise<SnmpVarbind[]>;
  walk(baseOid: string): Promise<SnmpVarbind[]>;
  /** Evict this target's session. Not "close my socket": there is one cache,
   *  and this is how a caller says the session is suspect. */
  close(): void;
}

export function openSnmpConnection(
  target: SnmpTarget,
  cache: SnmpSessionCache = snmpSessions,
): SnmpConnection {
  return {
    get: (oids) => snmpGet(target, oids, cache),
    walk: (baseOid) => snmpWalk(target, baseOid, cache),
    close: () => {
      try {
        cache.drop(target);
      } catch {
        // A target so malformed that it cannot even be keyed has no session to
        // drop. Callers use close() from a catch block; throwing a SECOND error
        // there would replace the real failure with this one.
      }
    },
  };
}

/**
 * Maximum varbinds in one GET PDU.
 *
 * 11 varbinds per interface (study section 3.1) means a 24-port switch needs
 * 264 — far past what fits in a 1472-byte UDP payload; an agent answering
 * `tooBig` drops the WHOLE response, so the poll of that device returns
 * nothing at all. 24 is deliberately conservative: about 600 bytes of
 * response, no fragmentation on any MTU a tunnel is likely to have.
 *
 * The study describes GETBULK with a tuned `max_repetitions` instead. Chunked
 * GET reaches the same 2-4 PDUs per device at our 8-interfaces-per-device
 * average, and it has one property GETBULK does not: the response varbinds come
 * back IN THE ORDER ASKED, one per requested OID, so a missing column is
 * unambiguous instead of shifting every subsequent value by one — the classic
 * way GETBULK puts the WAN octets on the LAN graph.
 */
export const MAX_VARBINDS_PER_PDU = 24;

/**
 * GET any number of OIDs, chunked. Returns a map keyed by the OID ASKED FOR.
 *
 * A chunk that fails fails the whole call: a partially-read interface is
 * exactly the AGENT_ERROR case, and stitching a half-response together is how
 * a counter gets paired with the previous cycle's timestamp.
 */
export async function getMany(
  connection: SnmpConnection,
  oids: string[],
  chunkSize = MAX_VARBINDS_PER_PDU,
): Promise<Map<string, SnmpVarbind>> {
  const out = new Map<string, SnmpVarbind>();
  for (let i = 0; i < oids.length; i += chunkSize) {
    const chunk = oids.slice(i, i + chunkSize);
    const varbinds = await connection.get(chunk);
    // Indexed POSITIONALLY by the OID we asked for. An agent is allowed to
    // normalise the OID it echoes back (leading dot, implicit .0); trusting its
    // spelling as the map key silently loses the varbind.
    for (let j = 0; j < chunk.length; j += 1) {
      const vb = varbinds[j];
      if (vb) out.set(chunk[j], { ...vb, oid: chunk[j] });
    }
  }
  return out;
}

// ============================================================================
// Identification
// ============================================================================

export interface SnmpIdentity {
  sysDescr: string | null;
  sysObjectID: string | null;
  sysName: string | null;
  sysUpTimeTicks: number | null;
  /** sysUpTime is in centiseconds and wraps at ~497 days. Converted here, and
   *  the caller must treat it as "at least this long", never as an absolute
   *  boot time. */
  uptimeSeconds: number | null;
  sysLocation: string | null;
  sysContact: string | null;
}

export async function snmpIdentify(
  target: SnmpTarget,
  cache: SnmpSessionCache = snmpSessions,
): Promise<SnmpIdentity> {
  const oids = [
    SYSTEM_OID.sysDescr,
    SYSTEM_OID.sysObjectID,
    SYSTEM_OID.sysName,
    SYSTEM_OID.sysUpTime,
    SYSTEM_OID.sysLocation,
    SYSTEM_OID.sysContact,
  ];
  const varbinds = await snmpGet(target, oids, cache);
  const byOid = new Map(varbinds.map((v) => [v.oid, v]));
  const str = (oid: string): string | null => {
    const vb = byOid.get(oid);
    if (!vb || vb.missing || vb.value === null) return null;
    const s = String(vb.value).trim();
    return s.length > 0 ? s : null;
  };
  const num = (oid: string): number | null => {
    const vb = byOid.get(oid);
    if (!vb || vb.missing || vb.value === null) return null;
    const n = Number(vb.value);
    return Number.isFinite(n) ? n : null;
  };

  const ticks = num(SYSTEM_OID.sysUpTime);
  return {
    sysDescr: str(SYSTEM_OID.sysDescr),
    sysObjectID: str(SYSTEM_OID.sysObjectID),
    sysName: str(SYSTEM_OID.sysName),
    sysUpTimeTicks: ticks,
    uptimeSeconds: ticks === null ? null : Math.floor(ticks / 100),
    sysLocation: str(SYSTEM_OID.sysLocation),
    sysContact: str(SYSTEM_OID.sysContact),
  };
}

/**
 * Brand from an SNMP answer. `sysObjectID` first — it is an OID under the
 * vendor's enterprise arc and cannot be spoofed by a description string — and
 * `sysDescr` only as a fallback, because a Vigor whose sysDescr reads "Router"
 * tells us nothing.
 *
 * Returns `null` rather than guessing. A wrong brand picks a wrong driver,
 * which picks a wrong command dialect: an unknown device in the inventory is
 * strictly better than a confidently mislabelled one.
 */
export function brandFromSnmp(
  identity: Pick<SnmpIdentity, 'sysObjectID' | 'sysDescr'>,
): 'mikrotik' | 'draytek' | 'zyxel' | 'sonicwall' | null {
  const oid = identity.sysObjectID ?? '';
  for (const [brand, arc] of Object.entries(ENTERPRISE_OID)) {
    if (oid === arc || oid.startsWith(`${arc}.`)) {
      return brand as 'mikrotik' | 'draytek' | 'zyxel' | 'sonicwall';
    }
  }
  const descr = (identity.sysDescr ?? '').toLowerCase();
  if (/routeros|mikrotik/.test(descr)) return 'mikrotik';
  if (/draytek|vigor/.test(descr)) return 'draytek';
  if (/zyxel|zywall|usg |nebula/.test(descr)) return 'zyxel';
  if (/sonicwall|sonicos/.test(descr)) return 'sonicwall';
  return null;
}
