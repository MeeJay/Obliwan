/**
 * ObliWAN — RouterOS transport.
 *
 * Layering, bottom to top:
 *   protocol.ts     bytes <-> sentences. Pure, no I/O, no timers.
 *   connection.ts   one authenticated session, multiplexed by `.tag=`.
 *   capabilities.ts what THIS firmware can do and where its menus live (R11).
 *   pool.ts         one persistent session per device, breaker + anti-stampede.
 *
 * Callers should reach for `RouterOsPool.withConnection()` and the capability
 * matrix. Nothing above this folder should import `protocol.ts` directly, and
 * nothing anywhere should hard-code a RouterOS menu path.
 */

export {
  MAX_WORD_LENGTH,
  SentenceReader,
  RouterOsProtocolError,
  RouterOsTrapError,
  RouterOsFatalError,
  encodeLength,
  encodeWord,
  encodeSentence,
  peekLength,
  parseSentence,
  rowsOf,
  redactWord,
  redactWords,
  commandOf,
} from './protocol';
export type { Sentence, SentenceType, LengthHeader } from './protocol';

export {
  ROUTEROS_PLAIN_PORT,
  ROUTEROS_TLS_PORT,
  RouterOsConnection,
  RouterOsTimeoutError,
  RouterOsConnectionClosedError,
  RouterOsAuthError,
  RouterOsFingerprintError,
  createRouterOsConnection,
} from './connection';
export type {
  RouterOsConnectionOptions,
  TalkOptions,
  StreamOptions,
  RouterOsStream,
  ConnectionState,
} from './connection';

export {
  probeCapabilities,
  getCapabilities,
  peekCapabilities,
  invalidateCapabilities,
  clearCapabilityCache,
  toDeviceCapabilities,
  parseRouterOsVersion,
  familyForVersion,
} from './capabilities';
export type {
  RouterOsCapabilityMatrix,
  RouterOsPaths,
  HealthShape,
  ParsedVersion,
} from './capabilities';

export {
  RouterOsPool,
  TokenBucket,
  CircuitOpenError,
  computeBackoffMs,
} from './pool';
export type {
  RouterOsTarget,
  RouterOsPoolHooks,
  RouterOsPoolOptions,
  DeviceHealthSnapshot,
} from './pool';
