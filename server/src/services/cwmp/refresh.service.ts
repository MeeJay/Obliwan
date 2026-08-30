/**
 * ObliWAN — "refresh this CPE now", answered honestly.
 *
 * ┌─ THE BUTTON THIS FILE REFUSES TO IMPLEMENT ───────────────────────────────┐
 * │ Every ACS UI has a Refresh button. Behind it is TR-069 Connection         │
 * │ Request: the ACS makes an HTTP GET to the `ConnectionRequestURL` the CPE  │
 * │ announced, and the CPE opens a session immediately.                       │
 * │                                                                          │
 * │ On this product's estate that URL is a PRIVATE address behind carrier     │
 * │ NAT. Making it reachable means STUN (TR-069 Annex G) or XMPP (TR-069      │
 * │ Amendment 5): a UDP binding the CPE must keep alive, that expires in      │
 * │ 30-120 seconds on most carrier NATs, against a server we would have to    │
 * │ run and monitor. The arbitrage is that the success rate does not justify  │
 * │ the machinery — and, more importantly, that a button which works 40 % of  │
 * │ the time is worse than no button, because the operator cannot tell the    │
 * │ 60 % from a broken CPE.                                                   │
 * │                                                                          │
 * │ So ObliWAN does the only thing that actually works: it LOWERS the inform  │
 * │ interval and tells the operator when the box will call in. That answer is │
 * │ a typed value (`CwmpRefreshOutcome`), it carries its own explanation      │
 * │ verbatim, and `connectionRequestSupported` is `false` on every device DTO │
 * │ so the client cannot draw the button by accident.                         │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY THIS IS ALLOWED TO WRITE WITHOUT A CHANGE JOB ───────────────────────┐
 * │ It sets `ManagementServer.PeriodicInformInterval`, which is on the very   │
 * │ short `ACS_PLUMBING_SUFFIXES` whitelist in `task.service.ts`. The         │
 * │ justification is written there, next to the whitelist, because that is    │
 * │ where a future reader will be deciding whether to add a third entry.      │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import { db } from '../../db';
import { config } from '../../config';
import { logger } from '../../utils/logger';
import {
  CWMP_NO_CONNECTION_REQUEST_EXPLANATION,
  CWMP_ROOT_PREFIX,
  type CwmpRefreshOutcome,
  type CwmpDataModel,
} from './contract';
import { enqueueTask, listTasks } from './task.service';

export async function requestRefresh(
  deviceId: number,
  userId: number | null,
): Promise<CwmpRefreshOutcome> {
  const cpe = (await db('cwmp_devices')
    .where({ device_id: deviceId })
    .first('data_model', 'last_inform_at', 'periodic_inform_interval')) as
    | {
        data_model: CwmpDataModel;
        last_inform_at: Date | null;
        periodic_inform_interval: number;
      }
    | undefined;

  if (!cpe) {
    return {
      supported: false,
      action: 'device_never_seen',
      etaSeconds: null,
      requestedInterval: config.cwmp.refreshIntervalSeconds,
      explanation:
        'This device is not enrolled in the ACS, so there is nothing to refresh. ' +
        CWMP_NO_CONNECTION_REQUEST_EXPLANATION,
    };
  }

  const target = Math.max(30, config.cwmp.refreshIntervalSeconds);
  const path = `${CWMP_ROOT_PREFIX[cpe.data_model]}ManagementServer.PeriodicInformInterval`;

  // A second click while the first request is still queued must not stack a
  // second write. The queued task IS the pending request; say so.
  const pending = await listTasks(deviceId, { states: ['queued', 'sent'], limit: 20 });
  const alreadyQueued = pending.some(
    (t) =>
      t.payload.kind === 'set_parameter_values' &&
      t.payload.ops.some((op) => op.path === path),
  );

  const eta = estimateEta(cpe.last_inform_at, cpe.periodic_inform_interval);

  if (alreadyQueued) {
    return {
      supported: false,
      action: 'already_pending',
      etaSeconds: eta,
      requestedInterval: target,
      explanation: CWMP_NO_CONNECTION_REQUEST_EXPLANATION,
    };
  }

  await enqueueTask(
    deviceId,
    {
      kind: 'set_parameter_values',
      ops: [{ path, valueType: 'xsd:unsignedInt', value: String(target) }],
    },
    {
      createdBy: userId,
      ttlSeconds: 3600,
      maxAttempts: 2,
      // The narrow, whitelisted exception to D3. Verified in `enqueueTask`.
      acsPlumbing: true,
    },
  );

  logger.info({ deviceId, target }, 'ACS: refresh requested — inform interval lowered');

  return {
    supported: false,
    action: 'periodic_interval_lowered',
    etaSeconds: eta,
    requestedInterval: target,
    explanation: CWMP_NO_CONNECTION_REQUEST_EXPLANATION,
  };
}

/**
 * When the CPE is next expected.
 *
 * The estimate is the REMAINDER of the current interval, not the new one: the
 * box has not been told about the new interval yet, and it will not be until it
 * calls in on the old one. Returning the new interval here would be the same
 * flavour of lie as the button this file refuses to draw.
 */
function estimateEta(lastInformAt: Date | null, interval: number): number | null {
  if (!lastInformAt) return null;
  const elapsed = (Date.now() - lastInformAt.getTime()) / 1000;
  const remaining = Math.max(0, interval - elapsed);
  return Math.round(remaining);
}
