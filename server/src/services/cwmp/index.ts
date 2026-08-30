/**
 * ObliWAN — the ACS service barrel.
 *
 * Import from here, not from a sibling file. The one exception is
 * `contract.ts`, which is re-exported below so `@obliwan/shared/dist/cwmp` is
 * named in exactly one place in the server.
 *
 * The RUNTIME (the 7547 listener and the sweepers) is NOT here: it lives in
 * `server/src/cwmp/index.ts`, next to the Express app it arms. Same split as
 * `services/snmp` vs. the transports, and for the same reason — one owner per
 * lifecycle.
 */

export * from './contract';

export {
  settingsForSlug,
  settingsForTenant,
  ensureSettingsForTenant,
  updateSettings,
  invalidateAcsSettings,
  ipMatchesCidrs,
  slugify,
  type AcsSettings,
} from './acsSettings.service';

export {
  AcsEnrolmentError,
  PROVISIONAL_CWMP_ID_PREFIX,
  applyInform,
  autoBind,
  bindProvisionalCwmpId,
  enrolDevice,
  findProvisionalCpe,
  ha1Of,
  isProvisionalCwmpId,
  mergeQuirks,
  provisionalCwmpId,
  refreshReachability,
  resolveCpe,
  type CwmpDeviceRow,
  type ResolvedCpe,
} from './device.service';

export {
  knownPaths,
  listParameters,
  upsertParameters,
  valuesFor,
  type IncomingParameter,
} from './parameter.service';

export {
  TaskRefusedError,
  cancelTask,
  claimNextTask,
  completeTask,
  countPending,
  enqueueTask,
  expireStaleTasks,
  failTask,
  getTask,
  getTaskByCommandKey,
  isAcsPlumbingPath,
  listTasks,
  newCommandKey,
  requeueSentTask,
} from './task.service';

export {
  SESSION_COOKIE,
  closeSession,
  hasOpenSessionFor,
  listUnknownCallers,
  matchSession,
  reapIdleSessions,
  type AuthenticatedCwmpSession,
  type CwmpSession,
  type SessionMatch,
} from './session.service';

export {
  canonicalValues,
  deleteMapping,
  generalise,
  learnFromTree,
  listMappings,
  mappingsFor,
  resolvePaths,
  unmappedKeys,
  upsertMapping,
  type MappingContext,
} from './paramMap.service';

export {
  TransferRefusedError,
  assertFileFitsDevice,
  completeTransfer,
  createTransfer,
  expireStaleTransfers,
  getFile,
  listFiles,
  listTransfers,
  markFetched,
  resolveToken,
  type CwmpFileRecord,
  type TransferRecord,
} from './transfer.service';

export {
  invalidateRpcLogGate,
  loggingEnabledFor,
  logRpc,
  mentionsSecretPath,
  readRpcLog,
  redactEnvelope,
  redactFault,
  taskSecretPlaintexts,
} from './rpcLog.service';

export { coverageReport } from './coverage.service';
export {
  cwmpConfigDocument,
  cwmpInventory,
  type CwmpInventoryFacts,
} from './inventory.service';
export { requestRefresh } from './refresh.service';

export {
  handleCwmpPost,
  type CwmpHttpRequest,
  type CwmpHttpResponse,
} from './sessionMachine';
