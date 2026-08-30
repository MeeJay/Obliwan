/**
 * ObliWAN — transport layer barrel.
 *
 * Four channels live here: `ssh`, `snmp`, `rest`, and the arbiter that chooses
 * between them. The fifth, `routeros_api`, lives in `./routeros/` and is owned
 * by another workstream — it is deliberately NOT re-exported here, so that this
 * barrel keeps compiling whether or not that folder is present. The MikroTik
 * driver reaches it through the registration seam in
 * `../drivers/mikrotik/routerosChannel.ts`.
 *
 * The sixth "transport" of decision D2, CWMP, is not a client at all: the CPE
 * dials us on port 7547. It arrives at M10 and has no entry here.
 */

export {
  SshTransport,
  SshShell,
  withSsh,
  type SshTarget,
  type SshExecResult,
  type SshExecOptions,
} from './ssh.transport';

// The SNMP channel. `snmp.transport.ts` is the ONLY owner of SNMP session
// lifecycle in the server — one `lru-cache`, one `dispose()`, one retry budget,
// one error classification. The M3 telemetry folder (`services/snmp/`) consumes
// it from here rather than keeping its own client.
export {
  SnmpSessionCache,
  snmpSessions,
  openSnmpConnection,
  snmpGet,
  snmpWalk,
  snmpIdentify,
  getMany,
  brandFromSnmp,
  classifySnmpError,
  decodeVarbind,
  dialTarget,
  securityLevelOf,
  asCounter,
  asInt,
  asText,
  ASN1,
  MAX_VARBINDS_PER_PDU,
  SYSTEM_OID,
  ENTERPRISE_OID,
  type SnmpTarget,
  type SnmpDialTarget,
  type SnmpCredentials,
  type SnmpVersionInput,
  type SnmpIdentity,
  type SnmpVarbind,
  type SnmpConnection,
  type SnmpSessionLike,
  type SnmpSessionFactory,
  type SnmpSessionCacheOptions,
} from './snmp.transport';

export {
  RestTransport,
  SonicOsSession,
  withSonicOsSession,
  NebulaClient,
  takeNebulaToken,
  resetNebulaBuckets,
  assertTlsConfig,
  retryDelayMs,
  httpError,
  type RestTarget,
  type RestResponse,
  type RestRequestOptions,
  type SonicOsCredentials,
  type NebulaConfig,
} from './rest.transport';

export {
  TransportArbiter,
  transportArbiter,
  DeferredIntentQueue,
  DbHealthStore,
  chooseChannel,
  computeBackoffMs,
  onFailure,
  onSuccess,
  defaultHealth,
  DEFAULT_BREAKER,
  TRANSPORT_INTENTS,
  type TransportIntent,
  type TransportHealth,
  type ArbiterDecision,
  type HealthStore,
  type BreakerPolicy,
  type DeferredIntent,
} from './arbiter.service';
