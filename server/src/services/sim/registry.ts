/**
 * ObliWAN F9 — connector registry.
 *
 * The one place a platform key becomes an implementation. Total over
 * `SimPlatform` rather than `Partial`, so adding a value to the vocabulary in
 * `shared/src/sim.ts` fails to compile here until somebody decides what it
 * does — including deciding that it refuses, which is what CFAST does.
 *
 * A `Partial` map would compile, return `undefined`, and the sweep would skip
 * the account. That is the shape of defect §11.1 motif 2 keeps finding: a rule
 * that exists and never runs.
 */

import { SIM_PLATFORM_CATALOG, type SimPlatform } from '@obliwan/shared';
import { cfastConnector } from './cfast.connector';
import { phenixConnector } from './phenix.connector';
import { SIM_RECHARGE_ADAPTERS, type SimConnector, type SimRechargeAdapter } from './types';

const CONNECTORS: Record<SimPlatform, SimConnector> = {
  phenix: phenixConnector,
  cfast: cfastConnector,
};

export function getConnector(platform: SimPlatform): SimConnector {
  return CONNECTORS[platform];
}

/**
 * Platforms the timed sweep may dial TODAY. Everything else is fed, not polled.
 *
 * `isPollable` is the one used on the live path (`account.pollableAccounts`
 * filters per row, and `line.fleetSummary` asks per account). A
 * `pollablePlatforms()` listing the set existed here with no caller at all —
 * §11.1 motif 2 — and has been removed rather than left as a rule nobody runs.
 *
 * TWO conditions, and the second one was missing until CFAST's documentation
 * was actually read. `ingestion` describes what the PARTNER offers;
 * `readImplemented` describes what ObliWAN has built. The first draft had only
 * the first test, which made the two inseparable: correcting CFAST's declared
 * shape from `push` to `pull` — a documentation fix, changing no behaviour on
 * purpose — would have silently put a connector that refuses every read onto a
 * four-hourly timer, raising a NOT_IMPLEMENTED error nobody can clear and
 * painting a permanent partner-unhealthy banner on every tenant dashboard.
 * That is precisely the always-on banner `fleetSummary` documents at length as
 * the thing not to ship.
 *
 * So: a platform becomes pollable when somebody writes the connector and flips
 * `readImplemented` in the same commit, never as a side effect of describing
 * the partner more accurately.
 */
export function isPollable(platform: SimPlatform): boolean {
  return (
    CONNECTORS[platform].ingestion.includes('pull') &&
    SIM_PLATFORM_CATALOG.some((p) => p.platform === platform && p.readImplemented)
  );
}

export function getRechargeAdapter(platform: SimPlatform): SimRechargeAdapter | undefined {
  return SIM_RECHARGE_ADAPTERS[platform];
}

/** True when ObliWAN can buy on this platform by itself. False everywhere. */
export function canExecuteRecharge(platform: SimPlatform): boolean {
  return SIM_RECHARGE_ADAPTERS[platform] !== undefined;
}

/**
 * Boot-time consistency check between the shared catalogue and the code.
 *
 * `SIM_PLATFORM_CATALOG` is what the UI renders; this registry is what actually
 * runs. A catalogue claiming `readImplemented: true` for a connector that
 * refuses, or `rechargeImplemented: true` with an empty adapter registry, is a
 * product that promises to watch a fleet it is not watching — and it is exactly
 * the kind of drift that survives a review because both files look right on
 * their own. Called from `startSimRuntime`, so it fails where it is seen.
 */
export function assertCatalogMatchesRegistry(): string[] {
  const problems: string[] = [];
  for (const info of SIM_PLATFORM_CATALOG) {
    const connector = CONNECTORS[info.platform];
    if (!connector) {
      problems.push(`${info.platform}: declared in the catalogue, absent from the registry`);
      continue;
    }
    const claimsRecharge = info.rechargeImplemented;
    const hasAdapter = canExecuteRecharge(info.platform);
    if (claimsRecharge !== hasAdapter) {
      problems.push(
        `${info.platform}: catalogue says rechargeImplemented=${claimsRecharge} but the ` +
          `adapter registry ${hasAdapter ? 'has' : 'has no'} entry`,
      );
    }
    if (info.readImplemented && !connector.ingestion.some((k) => k === 'pull' || k === 'push')) {
      problems.push(
        `${info.platform}: catalogue says readImplemented=true but the connector declares ` +
          `neither pull nor push ingestion`,
      );
    }
  }
  return problems;
}
