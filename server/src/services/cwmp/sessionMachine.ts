/**
 * ObliWAN — the CWMP session machine. One function, one POST, one decision.
 *
 * ┌─ THE ONE SENTENCE THAT SHAPES THIS WHOLE FILE ────────────────────────────┐
 * │ AN EMPTY POST IS A PROTOCOL SIGNAL, NOT AN ERROR.                         │
 * │                                                                          │
 * │ TR-069 §3.7.1.4: within a session the CPE always speaks first, and when   │
 * │ it has nothing left to say it sends an HTTP POST with an EMPTY BODY. That │
 * │ empty body is the CPE handing the ACS the floor, and it is the ONLY       │
 * │ moment at which the ACS is allowed to send a request. An implementation   │
 * │ that treats a zero-length body as a bad request — which is the default    │
 * │ behaviour of every JSON body parser and most WAFs — can never send a      │
 * │ single RPC. The whole ACS is dead and every symptom points elsewhere.     │
 * │                                                                          │
 * │ Hence `express.text({ type: () => true })` in `cwmpApp.ts`, and hence     │
 * │ `handleEmptyPost` being the first branch here rather than a guard clause. │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE STATES, AND THE THREE PLACES A TASK CAN GET STUCK ───────────────────┐
 * │   POST(Inform)      -> authenticate, record, open session, InformResponse │
 * │   POST(empty)       -> claim a task, send its RPC   (or 204 and close)    │
 * │   POST(xxxResponse) -> complete the task, send the NEXT RPC (pipelined)   │
 * │   POST(Fault)       -> fail the task, send the next RPC                   │
 * │                                                                          │
 * │ A task is in `sent` from the moment its RPC leaves until the CPE answers. │
 * │ It can get stuck there three ways, and each has an owner:                 │
 * │  - the CPE never answers      -> `reapIdleSessions` requeues it           │
 * │  - the session is superseded  -> `openSession` closes the old one         │
 * │  - the process dies           -> the row survives; the reaper finds it    │
 * │ There is no fourth way, and that is the property to preserve.             │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ ONE AUTHENTICATION GATE, ABOVE ALL FOUR BRANCHES ────────────────────────┐
 * │ Only the Inform may run without a session, because the Inform IS the      │
 * │ authentication exchange. Every other branch goes through the gate in      │
 * │ `handleCwmpPost`, which resolves the session ONCE — by cookie, scoped to  │
 * │ the tenant of the URL — and refuses it unless it is authenticated.        │
 * │                                                                          │
 * │ It used to be one `if` inside `handleEmptyPost`, which is one branch of   │
 * │ four. The other three ingested parameters, completed tasks and collected  │
 * │ dispatched RPCs on sessions that had proved nothing.                      │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import { config } from '../../config';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import {
  buildDownload,
  buildFault,
  buildGetParameterValues,
  buildGetRpcMethodsResponse,
  buildInformResponse,
  buildReboot,
  buildSetParameterValues,
  buildTransferCompleteResponse,
  CwmpParseError,
  parseEnvelope,
  parseInform,
  parseParameterList,
  parseSetStatus,
  parseTransferComplete,
  type SerialisableSetOp,
} from '../../cwmp/xml';
import { buildChallenge, digestNc, parseAuthorization, verifyDigest } from '../../cwmp/digest';
import { decrypt } from '../secretVault.service';
import {
  CWMP_FAULT,
  CWMP_ROOT_PREFIX,
  buildCwmpId,
  informIsBootstrap,
  isSecretParameterPath,
  type CwmpQuirks,
  type CwmpTask,
} from './contract';
import { ipMatchesCidrs, settingsForSlug, type AcsSettings } from './acsSettings.service';
import {
  applyInform,
  autoBind,
  bindProvisionalCwmpId,
  claimDigestNonce,
  findProvisionalCpe,
  ha1Of,
  mergeQuirks,
  resolveCpe,
  type ResolvedCpe,
} from './device.service';
import { upsertParameters } from './parameter.service';
import { learnFromTree } from './paramMap.service';
import { knownPaths, valuesFor } from './parameter.service';
import {
  claimNextTask,
  completeTask,
  enqueueTask,
  failTask,
  getTask,
  requeueSentTask,
} from './task.service';
import {
  SESSION_COOKIE,
  closeSession,
  hasOpenSessionFor,
  matchSession,
  openSession,
  touchSession,
  type AuthenticatedCwmpSession,
  type SessionMatch,
} from './session.service';
import { completeTransfer, createTransfer, getFile } from './transfer.service';
import { logRpc, redactFault, taskSecretPlaintexts } from './rpcLog.service';

export interface CwmpHttpRequest {
  slug: string;
  /** Raw body. `''` is the protocol signal — see the header. */
  body: string;
  sourceIp: string;
  /** The `ACSsession` cookie value, if the CPE echoed it. */
  cookieToken: string | null;
  authorization: string | undefined;
  /** The path the CPE POSTed to, for HA2 = MD5(method:uri). */
  requestUri: string;
}

export interface CwmpHttpResponse {
  status: number;
  body: string;
  headers: Record<string, string>;
  /** Set when a new session was opened, so the app can emit `Set-Cookie`. */
  setSessionCookie?: string;
}

const XML_HEADERS = { 'Content-Type': 'text/xml; charset=utf-8' };

/** 204 with an empty body: "I have nothing for you, hang up." */
function noContent(): CwmpHttpResponse {
  return { status: 204, body: '', headers: {} };
}

function xml(body: string, status = 200): CwmpHttpResponse {
  return { status, body, headers: { ...XML_HEADERS } };
}

function challenge(settings: AcsSettings, sourceIp: string, stale = false): CwmpHttpResponse {
  return {
    status: 401,
    body: '',
    headers: {
      'WWW-Authenticate':
        buildChallenge(settings.digestRealm, sourceIp) + (stale ? ', stale=true' : ''),
    },
  };
}

// ============================================================================
// Entry point
// ============================================================================

export async function handleCwmpPost(req: CwmpHttpRequest): Promise<CwmpHttpResponse> {
  const settings = await settingsForSlug(req.slug);
  if (!settings) {
    // A slug nobody recognises. 404 and NOT a default tenant: a fallback here
    // would file a mis-provisioned CPE under somebody else's customer (R4).
    logger.warn({ slug: req.slug, sourceIp: req.sourceIp }, 'ACS: POST to an unknown tenant slug');
    return { status: 404, body: '', headers: {} };
  }

  if (!ipMatchesCidrs(req.sourceIp, settings.trustedCidrs)) {
    logger.warn(
      { slug: req.slug, sourceIp: req.sourceIp },
      'ACS: source address outside the tenant trusted CIDRs',
    );
    return { status: 403, body: '', headers: {} };
  }

  if (req.body.trim().length === 0) return handleEmptyPost(req, settings);

  let parsed;
  try {
    parsed = parseEnvelope(req.body);
  } catch (err) {
    const message = err instanceof CwmpParseError ? err.message : String(err);
    logger.warn({ slug: req.slug, sourceIp: req.sourceIp, message }, 'ACS: unparseable envelope');
    await logRpc({
      deviceId: null,
      sessionId: null,
      direction: 'cpe_to_acs',
      method: null,
      cwmpId: null,
      httpStatus: 400,
      body: req.body,
    });
    // A fault, not a bare 400: a CPE that receives an HTTP error with no SOAP
    // body logs "ACS unreachable", which sends the operator looking at the
    // network. A CWMP fault says which envelope was wrong.
    return xml(buildFault('0', CWMP_FAULT.INVALID_ARGUMENTS, message), 400);
  }

  const rpcId = parsed.id ?? '1';

  // ── The Inform is the ONLY branch that may run without a session ─────────
  //
  // It IS the authentication exchange: it carries the CPE's identity and its
  // Digest response, and everything it does before that response verifies is
  // read-only (record the knock, challenge, refuse).
  if (parsed.method === 'Inform') {
    return handleInform(req, settings, parsed.body, rpcId, parsed.missingId);
  }

  // ┌─ THE GATE. ABOVE THE SWITCH, SO A BRANCH CANNOT BE ADDED BELOW IT AND ──┐
  // │ QUIETLY SKIP IT.                                                        │
  // │                                                                        │
  // │ A CPE that never proved who it is gets NOTHING: it does not ingest a    │
  // │ parameter, does not complete or fail a task, and does not receive an    │
  // │ RPC. This used to be a single `if` inside `handleEmptyPost` — one       │
  // │ branch of four — while `handleRpcResponse`, `handleCpeFault` and        │
  // │ `handleTransferComplete` reached the same machinery through a helper    │
  // │ that never tested `authenticated`. A forged `GetParameterValuesResponse`│
  // │ with an empty ParameterList, twelve lines of XML and no credential at   │
  // │ all, therefore both wrote into `cwmp_parameters` and collected the next │
  // │ queued `SetParameterValues` with a vault value resolved into it.        │
  // │                                                                        │
  // │ `matchSession` returns a union the branches cannot use without saying   │
  // │ which case they are in, so the next branch someone adds has to state    │
  // │ its answer to this question in order to compile.                        │
  // └─────────────────────────────────────────────────────────────────────────┘
  const match = await matchSession({ cookieToken: req.cookieToken, tenantId: settings.tenantId });
  if (match.kind !== 'authenticated') {
    await refuseUnauthenticated(match, req, settings);
    return noContent();
  }
  const session = match.session;

  switch (parsed.method) {
    case 'TransferComplete':
    case 'AutonomousTransferComplete':
      return handleTransferComplete(req, session, parsed.body, rpcId);
    case 'GetRPCMethods':
      return xml(buildGetRpcMethodsResponse(rpcId));
    case 'Fault':
      return handleCpeFault(req, session, settings, parsed.fault, rpcId);
    default:
      return handleRpcResponse(req, session, settings, parsed.method ?? '', parsed.body, rpcId);
  }
}

/**
 * What happens to a POST that carries no session this tenant may act on.
 *
 * An unauthenticated session is CLOSED rather than left open. It is either a
 * CPE we recorded at the door (no credential stored, so nothing will ever be
 * dispatched to it) or somebody probing, and in both cases leaving the row open
 * only gives the next POST something to try to adopt.
 *
 * `kind: 'none'` also covers the cross-tenant case: a cookie minted under
 * another customer's slug does not resolve here at all, because `matchSession`
 * joins `devices` on the tenant of the URL.
 */
async function refuseUnauthenticated(
  match: SessionMatch,
  req: CwmpHttpRequest,
  settings: AcsSettings,
): Promise<void> {
  if (match.kind === 'unauthenticated') {
    logger.warn(
      { sessionId: match.session.id, deviceId: match.session.deviceId, slug: req.slug },
      'ACS: POST on a session that never authenticated — refused and closed',
    );
    await closeSession(match.session.id, 'closed');
    return;
  }
  logger.debug(
    { slug: req.slug, tenantId: settings.tenantId, hadCookie: req.cookieToken !== null },
    'ACS: POST with no open session of this tenant — nothing to do',
  );
}

// ============================================================================
// Inform
// ============================================================================

async function handleInform(
  req: CwmpHttpRequest,
  settings: AcsSettings,
  body: Record<string, unknown>,
  rpcId: string,
  missingId: boolean,
): Promise<CwmpHttpResponse> {
  const inform = parseInform(body);

  if (!inform.oui || !inform.serialNumber) {
    return xml(
      buildFault(rpcId, CWMP_FAULT.INVALID_ARGUMENTS, 'Inform without OUI or SerialNumber'),
      400,
    );
  }

  const cwmpId = buildCwmpId({
    oui: inform.oui,
    productClass: inform.productClass,
    serialNumber: inform.serialNumber,
  });

  // Observed, not configured. Every one of these was written because a real
  // envelope forced the parser to cope.
  const quirks: CwmpQuirks = {};
  if (missingId) quirks.noCwmpId = true;
  if (inform.arrayCountMismatch) quirks.arrayCountMismatch = true;
  if (inform.parameters.some((p) => p.typeWasBad)) quirks.badXsiType = true;
  if (
    inform.parameters.some((p) => p.path.startsWith(CWMP_ROOT_PREFIX.tr098)) &&
    inform.parameters.some((p) => p.path.startsWith(CWMP_ROOT_PREFIX.tr181))
  ) {
    quirks.mixedDataModel = true;
  }

  let cpe = await resolveCpe(cwmpId, settings.tenantId);
  let provisionalDeviceId: number | null = null;

  // ── The device an operator enrolled, calling in for the first time ───────
  //
  // `enrolDevice()` had to write a `cwmp_id` before this box had ever spoken,
  // so it wrote `PENDING-<deviceId>-<inventory serial>`. `resolveCpe` can never
  // match that — the CPE announces `OUI-ProductClass-Serial` — and `autoBind`
  // refuses any device that already has a `cwmp_devices` row, which is exactly
  // what an enrolled device has. So an enrolled DrayTek was challenged for ever
  // and no operator action unstuck it.
  //
  // The row is FOUND on the inventory serial, which is a sticker and not an
  // authorisation, and it is BOUND below — only after the Digest response
  // verifies against the HA1 the enrolment stored.
  if (!cpe) {
    const pending = await findProvisionalCpe(settings.tenantId, inform.serialNumber);
    if (pending) {
      cpe = pending;
      provisionalDeviceId = pending.deviceId;
    }
  }

  // ── The knock at the door ────────────────────────────────────────────────
  if (!cpe) {
    if (settings.allowAutoEnroll) {
      const boundId = await autoBind(settings.tenantId, inform.serialNumber, cwmpId);
      if (boundId !== null) cpe = await resolveCpe(cwmpId, settings.tenantId);
    }
  }

  if (!cpe) {
    // RECORDED, not enrolled. An operator sees it on the ACS screen and binds
    // it by hand — `discoveries`, migration 002, applied to TR-069.
    await openSession({
      deviceId: null,
      cwmpId,
      sourceIp: req.sourceIp,
      authenticated: false,
    });
    logger.info(
      { cwmpId, sourceIp: req.sourceIp, tenantId: settings.tenantId },
      'ACS: Inform from an unknown CPE — recorded, not enrolled',
    );
    return challenge(settings, req.sourceIp);
  }

  // ── Authentication ───────────────────────────────────────────────────────
  const ha1 = ha1Of(cpe.cwmp);
  let authenticated = false;

  if (ha1) {
    const creds = parseAuthorization(req.authorization);
    if (!creds) return challenge(settings, req.sourceIp);

    if (creds.scheme === 'basic') {
      // The CPE will not do Digest. Recorded as a quirk and REFUSED — the
      // credential is not the problem and a fourth 401 would make the operator
      // believe it is.
      await mergeQuirks(cpe.deviceId, { basicAuthOnly: true });
      logger.warn(
        { deviceId: cpe.deviceId, cwmpId },
        'ACS: CPE offered Basic auth; ObliWAN requires Digest',
      );
      return challenge(settings, req.sourceIp);
    }

    const verdict = verifyDigest(creds, ha1, 'POST', req.requestUri, req.sourceIp);
    if (!verdict.ok) {
      if (!verdict.stale) {
        logger.warn(
          { deviceId: cpe.deviceId, cwmpId, reason: verdict.reason },
          'ACS: Digest verification failed',
        );
      }
      return challenge(settings, req.sourceIp, verdict.stale === true);
    }

    // ── The header is correct. Is it the FIRST time it is correct? ─────────
    //
    // This listener is plain HTTP by design (§6.2: the fleet's ACS URLs were
    // provisioned as `http://`), so an `Authorization: Digest …` header is
    // visible to anything on the path — the transit operator, a Wi-Fi AP, an
    // intermediate router. Without this, re-POSTing the captured header any
    // time in the next `NONCE_TTL_MS` opened a session with
    // `authenticated = true`, and everything the gate above protects followed
    // from there. `digest.ts` used to CLAIM this bound in its header without
    // implementing it anywhere; `claimDigestNonce` is where it now lives.
    //
    // A refusal is answered `stale=true`: an honest CPE whose nc collided (or
    // that sends no nc at all and retried after a lost response) recomputes
    // against a fresh nonce without prompting, which costs it one round trip.
    if (!(await claimDigestNonce(cpe.deviceId, creds.nonce!, digestNc(creds.nc)))) {
      logger.warn(
        { deviceId: cpe.deviceId, cwmpId, sourceIp: req.sourceIp },
        'ACS: Digest credentials already spent for this nonce — replay refused',
      );
      return challenge(settings, req.sourceIp, true);
    }
    authenticated = true;
  } else {
    // Enrolled but never given a credential — an auto-bound CPE. We LISTEN and
    // RECORD, and `handleEmptyPost` refuses to dispatch anything to an
    // unauthenticated session. Nothing is written to a box we cannot identify.
    logger.warn(
      { deviceId: cpe.deviceId, cwmpId },
      'ACS: CPE has no ACS credential — inform accepted read-only, no task will be dispatched',
    );
  }

  // ── The provisional identity is spent HERE, and only on a proof ──────────
  //
  // `findProvisionalCpe` only returns rows that HAVE a stored HA1, so the
  // branch above ran and `authenticated` is the verdict of a real Digest
  // check. Said again out loud anyway, because this is the line that turns a
  // serial number anybody can read off a sticker into an identity.
  if (provisionalDeviceId !== null) {
    if (!authenticated) return challenge(settings, req.sourceIp);

    const bound = await bindProvisionalCwmpId(provisionalDeviceId, cwmpId);
    if (!bound) {
      // Another row already holds this identity — the same box enrolled twice,
      // or two devices sharing a serial. Recorded as a knock so the operator
      // sees it on the ACS screen, and refused: guessing which row is right
      // would be the ACS binding a CPE to a customer on its own (R4).
      logger.error(
        { deviceId: provisionalDeviceId, cwmpId, tenantId: settings.tenantId },
        'ACS: cwmp_id already held by another device — provisional binding refused',
      );
      await openSession({
        deviceId: null,
        cwmpId,
        sourceIp: req.sourceIp,
        authenticated: false,
      });
      return challenge(settings, req.sourceIp);
    }
    cpe.cwmp.cwmp_id = cwmpId;
  }

  // ── The `noCookie` quirk, observed where it is safe to observe it ────────
  //
  // This Inform has passed Digest, so the identity is proved. A box informing
  // again while its PREVIOUS session is still open, having echoed no
  // `ACSsession` with this request, dropped the cookie: a cookie-honouring CPE
  // ends its session on our 204, which closes the row.
  //
  // It matters more than it used to. There is no address-keyed fallback any
  // more (see `session.service.ts`), so this quirk is the difference between a
  // box that can be handed an RPC and one that can only ever be read — and it
  // belongs on the device screen rather than being rediscovered later as "this
  // device's tasks never run".
  if (authenticated && req.cookieToken === null && (await hasOpenSessionFor(cwmpId))) {
    await mergeQuirks(cpe.deviceId, { noCookie: true });
    logger.warn(
      { deviceId: cpe.deviceId, cwmpId },
      'ACS: CPE did not echo the session cookie — it can be read but not driven',
    );
  }

  // ── Record ───────────────────────────────────────────────────────────────
  const session = await openSession({
    deviceId: cpe.deviceId,
    cwmpId,
    sourceIp: req.sourceIp,
    authenticated,
  });

  await logRpc({
    deviceId: cpe.deviceId,
    sessionId: session.id,
    direction: 'cpe_to_acs',
    method: 'Inform',
    cwmpId: rpcId,
    httpStatus: 200,
    body: req.body,
  });

  const paths = inform.parameters.map((p) => p.path);
  await applyInform(
    cpe.deviceId,
    {
      manufacturer: inform.manufacturer,
      oui: inform.oui,
      productClass: inform.productClass,
      serialNumber: inform.serialNumber,
      events: inform.events,
      parameterPaths: paths,
      hardwareVersion: pick(inform.parameters, /\.DeviceInfo\.HardwareVersion$/),
      softwareVersion: pick(inform.parameters, /\.DeviceInfo\.SoftwareVersion$/),
      connectionRequestUrl: pick(inform.parameters, /\.ManagementServer\.ConnectionRequestURL$/),
      periodicInformInterval: toInt(
        pick(inform.parameters, /\.ManagementServer\.PeriodicInformInterval$/),
      ),
      sourceIp: req.sourceIp,
      cwmpVersion: null,
    },
    quirks,
  );

  await upsertParameters(
    cpe.deviceId,
    inform.parameters.map((p) => ({
      path: p.path,
      value: p.value,
      valueType: p.valueType,
      writable: false,
    })),
  );

  // ── The one thing an Inform triggers on its own ──────────────────────────
  //
  // A BOOTSTRAP means the CPE has forgotten everything, and a first sighting
  // means we know nothing. Both need a full tree read, and a full tree read is
  // ONE GetParameterValues on the root partial path — no GetParameterNames, no
  // second RPC (arbitrage A1). This is also what feeds learn mode, which is why
  // learn mode is not a dead function waiting for a caller that never came.
  if (authenticated && (informIsBootstrap(inform.events) || cpe.cwmp.inform_count === 0)) {
    const root = CWMP_ROOT_PREFIX[cpe.cwmp.data_model];
    try {
      await enqueueTask(
        cpe.deviceId,
        { kind: 'get_parameter_values', paths: [root] },
        { ttlSeconds: 3600, maxAttempts: 2 },
      );
    } catch (err) {
      logger.warn({ err, deviceId: cpe.deviceId }, 'ACS: could not queue the discovery read');
    }
  }

  const response = buildInformResponse(rpcId);
  await logRpc({
    deviceId: cpe.deviceId,
    sessionId: session.id,
    direction: 'acs_to_cpe',
    method: 'InformResponse',
    cwmpId: rpcId,
    httpStatus: 200,
    body: response,
  });

  return { ...xml(response), setSessionCookie: session.sessionToken };
}

// ============================================================================
// The empty POST — the ACS's only turn to speak
// ============================================================================

async function handleEmptyPost(
  req: CwmpHttpRequest,
  settings: AcsSettings,
): Promise<CwmpHttpResponse> {
  // THE COOKIE OR NOTHING. There is no body to read an identity out of and the
  // source address is not one (see `session.service.ts`'s header, and A6: under
  // the shipped deployment every CPE in the fleet arrives from 172.18.0.1).
  // A CPE that dropped the cookie gets 204 here and must re-Inform.
  const match = await matchSession({ cookieToken: req.cookieToken, tenantId: settings.tenantId });
  if (match.kind !== 'authenticated') {
    await refuseUnauthenticated(match, req, settings);
    return noContent();
  }
  const session = match.session;

  // The CPE gave us the floor while an RPC of ours was still outstanding.
  // Protocol-wise that means it has abandoned the request; the task goes back
  // to the queue rather than sitting in `sent` until the reaper notices.
  if (session.pendingTaskId) {
    await requeueSentTask(session.pendingTaskId, 'CPE sent an empty POST instead of a response');
    await touchSession(session.id, { pendingTaskId: null, pendingRpcId: null });
  }

  return dispatchNextTask({ ...session, pendingTaskId: null }, req, settings);
}

/**
 * Claim a task and put its RPC on the wire, or end the session.
 *
 * The single place an ACS-to-CPE request is ever produced. Everything else in
 * this file routes here, which is what keeps "what may the ACS send" answerable
 * by reading one function.
 */
async function dispatchNextTask(
  session: AuthenticatedCwmpSession,
  req: CwmpHttpRequest,
  settings: AcsSettings,
): Promise<CwmpHttpResponse> {
  // `deviceId` is a number by TYPE here, not by a check that could be dropped:
  // only an `AuthenticatedCwmpSession` reaches this function, and only
  // `matchSession` produces one.
  const deviceId = session.deviceId;

  const task = await claimNextTask(deviceId);
  if (!task) {
    await closeSession(session.id, 'closed');
    return noContent();
  }

  let envelope: string;
  const rpcId = `acs-${task.id}-${task.attempts}`;

  try {
    envelope = await serialiseTask(task, deviceId, settings);
  } catch (err) {
    // A task we cannot even serialise is a task that will never work. Fail it
    // here rather than shipping a malformed envelope to a CPE that will answer
    // 9003 and burn an attempt.
    logger.error({ err, taskId: task.id }, 'ACS: task could not be serialised');
    await failTask(task.id, {
      faultCode: 'Server',
      code: CWMP_FAULT.INTERNAL_ERROR,
      faultString: err instanceof Error ? err.message : String(err),
    });
    return dispatchNextTask(session, req, settings);
  }

  await touchSession(session.id, {
    pendingTaskId: task.id,
    pendingRpcId: rpcId,
    incrementRpc: true,
  });

  await logRpc({
    deviceId,
    sessionId: session.id,
    direction: 'acs_to_cpe',
    method: task.kind,
    cwmpId: rpcId,
    httpStatus: 200,
    body: envelope,
  });

  return xml(envelope);
}

/**
 * Turn a task row into an envelope.
 *
 * THE SECRET RESOLUTION HAPPENS HERE AND NOWHERE ELSE (§8.2). A
 * `set_parameter_values` op carrying a `secretRef` is resolved from the vault
 * at this exact point — in memory, on the way to the socket — and the plaintext
 * exists for the length of one string concatenation. It is never in the task
 * row, never in a log (the rpc log redactor strips it on the way out), and
 * never in an API response.
 */
async function serialiseTask(
  task: CwmpTask,
  deviceId: number,
  settings: AcsSettings,
): Promise<string> {
  const rpcId = `acs-${task.id}-${task.attempts}`;

  switch (task.payload.kind) {
    case 'get_parameter_values':
      return buildGetParameterValues(rpcId, task.payload.paths);

    case 'set_parameter_values': {
      const ops: SerialisableSetOp[] = [];
      for (const op of task.payload.ops) {
        let value: string;
        if (op.secretRef !== undefined) {
          value = decrypt(op.secretRef);
        } else {
          value = op.value ?? '';
          if (isSecretParameterPath(op.path) && value.length > 0) {
            // A literal on a credential path means somebody bypassed the vault.
            // Refuse: the alternative is a plaintext credential in a task row,
            // which is the exact finding §8.2 exists to prevent.
            throw new Error(
              `refusing to write a literal value to the credential path ${op.path}; ` +
                'use a vault reference (secretRef)',
            );
          }
        }
        ops.push({ path: op.path, valueType: op.valueType, value });
      }
      return buildSetParameterValues(rpcId, ops, task.payload.parameterKey ?? task.commandKey);
    }

    case 'download': {
      const file = await getFile(task.payload.fileId, settings.tenantId);
      if (!file) throw new Error(`file ${task.payload.fileId} is gone`);
      const transfer = await createTransfer({
        deviceId,
        fileId: file.id,
        taskId: task.id,
        commandKey: task.commandKey,
      });
      const base = fileBaseUrl(settings);
      return buildDownload(rpcId, {
        commandKey: task.commandKey,
        fileType: task.payload.fileType,
        url: `${base}/cwmp-files/${transfer.urlToken}`,
        fileSize: file.sizeBytes,
        targetFileName: task.payload.targetFileName,
      });
    }

    case 'reboot':
      return buildReboot(rpcId, task.commandKey);
  }
}

function fileBaseUrl(_settings: AcsSettings): string {
  // Empty means "single-homed, derive from the Host header" — which the app
  // does. An explicit value is required the moment there is a NAT in front,
  // and getting it wrong is a firmware push that never starts.
  return config.cwmp.publicBaseUrl.replace(/\/+$/, '');
}

// ============================================================================
// RPC responses and faults
// ============================================================================

async function handleRpcResponse(
  req: CwmpHttpRequest,
  session: AuthenticatedCwmpSession,
  settings: AcsSettings,
  method: string,
  body: Record<string, unknown>,
  rpcId: string,
): Promise<CwmpHttpResponse> {
  await logRpc({
    deviceId: session.deviceId,
    sessionId: session.id,
    direction: 'cpe_to_acs',
    method,
    cwmpId: rpcId,
    httpStatus: 200,
    body: req.body,
  });

  if (method === 'GetParameterValuesResponse') {
    // WAS THIS A SUBTREE READ? A CWMP name ending in `.` is a PARTIAL PATH and
    // the answer is a whole branch of the tree; anything else is a targeted
    // read of a handful of leaves. Learn mode only makes sense on the first,
    // and the question is answered by the REQUEST we sent — not by counting
    // the leaves that came back, which would make the threshold a magic number
    // that a small CPE quietly falls under.
    const task = session.pendingTaskId ? await getTask(session.pendingTaskId) : null;
    const wasSubtreeRead =
      task?.payload.kind === 'get_parameter_values' &&
      task.payload.paths.some((path) => path.endsWith('.'));

    await ingestParameterValues(session.deviceId, body, wasSubtreeRead === true);
  }

  if (method === 'SetParameterValuesResponse' && parseSetStatus(body) === 1) {
    // TR-069: Status 0 = applied, Status 1 = APPLIED BUT NOT IN EFFECT UNTIL
    // THE CPE REBOOTS. The task succeeded either way, so the distinction is
    // invisible in the queue — and it is the difference between "the change is
    // live" and "the change is live the next time the customer power-cycles
    // their box", which is exactly what somebody will be trying to work out
    // three days later. Said out loud, once, at the moment it is known.
    logger.info(
      { deviceId: session.deviceId, taskId: session.pendingTaskId },
      'ACS: the CPE accepted the write but it takes effect only after a reboot (Status 1)',
    );
  }

  if (session.pendingTaskId) {
    await completeTask(session.pendingTaskId);
    await touchSession(session.id, { pendingTaskId: null, pendingRpcId: null });
  }

  // PIPELINED: the answer to the CPE's response IS the next request. One fewer
  // round trip per task, which on a CPE with a 30 s HTTP timeout and six queued
  // tasks is the difference between finishing the session and not.
  return dispatchNextTask({ ...session, pendingTaskId: null }, req, settings);
}

/**
 * Fold a GetParameterValuesResponse into the tree, then let learn mode look at
 * it.
 *
 * `fromSubtreeRead` is the gate: deriving a mapping from a three-parameter
 * targeted answer would generalise from almost nothing, and the caller knows
 * which kind of read it asked for.
 *
 * ┌─ THE TENANT COMES FROM THE DEVICE, NEVER FROM THE SLUG ───────────────────┐
 * │ This function used to take a `tenantId` argument, and the caller passed   │
 * │ the tenant of the URL alongside a `deviceId` that came from the session   │
 * │ cookie. When those two disagreed — a CPE of tenant A posting its own      │
 * │ legitimate cookie to `/tenant-b` — `learnFromTree` wrote A's parameter    │
 * │ paths, A's model string and A's device id into B's `cwmp_param_map`: the  │
 * │ table that translates `wan.external_ip` for B's drift engine and B's NCM  │
 * │ builders, and a screen B can read.                                        │
 * │                                                                          │
 * │ `matchSession` now refuses that pairing outright. This is the belt:       │
 * │ deriving the tenant from the DEVICE makes an inconsistent pair            │
 * │ UNREPRESENTABLE rather than merely unreachable.                           │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
async function ingestParameterValues(
  deviceId: number,
  body: Record<string, unknown>,
  fromSubtreeRead: boolean,
): Promise<void> {
  const { parameters, mismatch } = parseParameterList(body.ParameterList);
  if (parameters.length === 0) return;

  if (mismatch) await mergeQuirks(deviceId, { arrayCountMismatch: true });
  if (parameters.some((p) => p.typeWasBad)) await mergeQuirks(deviceId, { badXsiType: true });

  await upsertParameters(
    deviceId,
    parameters.map((p) => ({
      path: p.path,
      value: p.value,
      valueType: p.valueType,
      // A GetParameterValuesResponse does not carry writability; keeping the
      // stored flag would be a lie either way, so it stays false until a
      // GetParameterAttributes we do not implement says otherwise.
      writable: false,
    })),
  );

  if (!fromSubtreeRead) return;

  const meta = await deviceMeta(deviceId);
  if (!meta) return;
  try {
    const paths = await knownPaths(deviceId);
    const values = await valuesFor(deviceId, paths);
    await learnFromTree(
      {
        tenantId: meta.tenantId,
        dataModel: meta.dataModel,
        brand: meta.brand,
        model: meta.model,
        firmware: meta.firmware,
      },
      deviceId,
      paths,
      values,
    );
  } catch (err) {
    logger.warn({ err, deviceId }, 'ACS: learn mode failed (parameters were still stored)');
  }
}

/**
 * The CPE answered a fault.
 *
 * ┌─ A FAULT IS A PLACE A SECRET COMES BACK OUT (§8.2) ───────────────────────┐
 * │ `serialiseTask` decrypts a `secretRef` on the way to the socket. Firmware │
 * │ that refuses the value answers 9007 and — documented behaviour on DrayTek │
 * │ as on Zyxel — REPEATS THE REJECTED VALUE in its FaultString. `failTask`   │
 * │ then wrote that string verbatim into `cwmp_tasks.fault`: a column with no │
 * │ retention at all (unlike `cwmp_rpc_log`, dropped at seven days), served   │
 * │ by `GET /api/acs/devices/:id/tasks` right beside a payload summary that   │
 * │ was carefully rendered as "(from vault)".                                 │
 * │                                                                          │
 * │ So the fault is redacted BEFORE it is stored, and the raw envelope is     │
 * │ logged with those plaintexts named explicitly: `redactEnvelope` cannot    │
 * │ see them on its own, because a fault struct carries no `<Value>` element  │
 * │ for its first pass to key on.                                             │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
async function handleCpeFault(
  req: CwmpHttpRequest,
  session: AuthenticatedCwmpSession,
  settings: AcsSettings,
  fault: { faultCode: string; code: string; faultString: string } | null,
  rpcId: string,
): Promise<CwmpHttpResponse> {
  const task = session.pendingTaskId ? await getTask(session.pendingTaskId) : null;

  await logRpc({
    deviceId: session.deviceId,
    sessionId: session.id,
    direction: 'cpe_to_acs',
    method: 'Fault',
    cwmpId: rpcId,
    httpStatus: 200,
    body: req.body,
    scrub: taskSecretPlaintexts(task),
  });

  if (session.pendingTaskId && fault) {
    await failTask(session.pendingTaskId, redactFault(fault, task));
    await touchSession(session.id, { pendingTaskId: null, pendingRpcId: null });
  }
  return dispatchNextTask({ ...session, pendingTaskId: null }, req, settings);
}

async function handleTransferComplete(
  req: CwmpHttpRequest,
  session: AuthenticatedCwmpSession,
  body: Record<string, unknown>,
  rpcId: string,
): Promise<CwmpHttpResponse> {
  const tc = parseTransferComplete(body);

  // CORRELATED BY CommandKey AND NOTHING ELSE. This arrives in a later session
  // than the Download that caused it — possibly after a factory reset, from a
  // different address, with a different cookie — so the session is used for the
  // LOG and never for the match. It is nonetheless an AUTHENTICATED session:
  // the gate in `handleCwmpPost` sees to that, and completing a transfer moves
  // a task to a terminal state like any other write.
  const result = await completeTransfer({
    commandKey: tc.commandKey,
    faultCode: tc.faultCode,
    faultString: tc.faultString,
    startTime: tc.startTime,
    completeTime: tc.completeTime,
  });

  if (!result.matched) {
    logger.warn(
      { commandKey: tc.commandKey, deviceId: session.deviceId },
      'ACS: TransferComplete for a CommandKey this ACS never issued',
    );
  }

  await logRpc({
    deviceId: session.deviceId,
    sessionId: session.id,
    direction: 'cpe_to_acs',
    method: 'TransferComplete',
    cwmpId: rpcId,
    httpStatus: 200,
    body: req.body,
  });

  // The response is mandatory even for an unmatched CommandKey: a CPE that does
  // not get a TransferCompleteResponse retransmits the TransferComplete on
  // every session, forever.
  return xml(buildTransferCompleteResponse(rpcId));
}

// ============================================================================
// Helpers
// ============================================================================

async function deviceMeta(deviceId: number): Promise<{
  tenantId: number;
  dataModel: 'tr098' | 'tr181';
  brand: string;
  model: string | null;
  firmware: string | null;
} | null> {
  const cpe = await resolveCpeByDeviceId(deviceId);
  if (!cpe) return null;
  return {
    tenantId: cpe.tenantId,
    dataModel: cpe.cwmp.data_model,
    brand: cpe.brand,
    model: cpe.model,
    firmware: cpe.cwmp.software_version,
  };
}

/** Resolve by device id rather than by cwmp_id — used after authentication. */
async function resolveCpeByDeviceId(deviceId: number): Promise<ResolvedCpe | null> {
  const row = (await db('cwmp_devices as c')
    .join('devices as d', 'd.id', 'c.device_id')
    .where('c.device_id', deviceId)
    .first(
      'c.*',
      'd.tenant_id as d_tenant_id',
      'd.name as d_name',
      'd.brand as d_brand',
      'd.family as d_family',
      'd.model as d_model',
    )) as Record<string, unknown> | undefined;
  if (!row) return null;
  return {
    deviceId,
    tenantId: Number(row.d_tenant_id),
    deviceName: String(row.d_name),
    brand: String(row.d_brand),
    family: String(row.d_family),
    model: (row.d_model as string | null) ?? null,
    cwmp: row as never,
  };
}

function pick(
  params: ReadonlyArray<{ path: string; value: string }>,
  rx: RegExp,
): string | null {
  const hit = params.find((p) => rx.test(p.path));
  return hit && hit.value.trim().length > 0 ? hit.value.trim() : null;
}

function toInt(raw: string | null): number | null {
  if (raw === null) return null;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) ? n : null;
}

export { SESSION_COOKIE };
