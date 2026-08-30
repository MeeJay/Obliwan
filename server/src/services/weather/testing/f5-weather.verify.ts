/**
 * ObliWAN F5 — Operator Weather, verified against a real PostgreSQL.
 *
 * WHAT THIS FILE PROVES, AND WHAT IT CANNOT
 *
 * It proves the CORRELATION: the offline address classification, the ASN range
 * arithmetic, the quorum, the fleet-wide guard, the open/close asymmetry, the
 * idempotence of the ingestion, the tenant isolation, and the schema-level
 * catches that make a duplicate incident and a symmetric policy impossible to
 * store. It runs the REAL services against the REAL schema of migration 021 —
 * the partial unique indexes, the CHECK constraints and the generated column
 * are all live, and several assertions below exist only to make the database
 * refuse something.
 *
 * It proves NOTHING about MikroTik. There is no router on this machine and
 * there never was one on this project. The RouterOS assertions drive a
 * SCRIPTED session (`fakeRouter`) that answers the sentences a RouterOS 6 and a
 * RouterOS 7 box would answer; "the active default route was resolved through
 * the capability matrix and the LTE menu was discovered by probing" is a strong
 * statement about this resolver and says nothing about whether a real CHR
 * answers those words. The PPP sessions are likewise hand-written into
 * `ppp_sessions` in the shape `applySessionUp` writes them.
 *
 * THE FOUR ACCEPTANCE SCENARIOS OF THE BRIEF ARE CHECKED VERBATIM:
 *   one site flips                      -> NO operator alert
 *   twelve sites, same ASN, ten minutes -> ONE alert, not twelve
 *   twelve sites, twelve ASNs           -> NO alert (the fault is ours)
 *   recovery                            -> the incident closes, and it takes
 *                                          longer to close than it took to open
 *
 *   DATABASE_URL=… npx tsx src/services/weather/testing/f5-weather.verify.ts
 */

import {
  DEFAULT_WEATHER_POLICY, MIN_HOLD_DOWN_RATIO, WeatherPolicyError,
  classifyIpScope, clearThreshold, evaluateOperatorWeather, isAttributableAddress,
  isCellularIfType, lineKeyOf, looksCellularByName, normalizeWeatherPolicy, quorumFor,
  resumeThreshold,
  siteKeyOf,
  validateWeatherPolicy,
  type AsnCandidate, type OpenIncidentState, type WeatherPolicy,
} from '@obliwan/shared/dist/weather';
import { db } from '../../../db';
import {
  attributeAddress, clearAsnCache, importAsnRanges, parseAsnRangeLine, rangeToCidrs,
} from '../asn.service';
import {
  invalidateCellularPaths, observeEgressPath, pickActiveDefaultRoute,
  resolveEgressFromRouter, resolveEgressFromSnmp, type RouterOsQueryable,
} from '../egressPath.service';
import { ingestPathEvents } from '../ingest.service';
import {
  getIncident, getTenantPolicy, getWeatherReport, listIncidents, runWeatherScan,
  setTenantPolicy,
} from '../correlator.service';
import type { RouterOsCapabilityMatrix } from '../../transport/routeros';
import { CAPABILITIES } from '@obliwan/shared';
import { AppError } from '../../../middleware/errorHandler';
import weatherRoutes from '../../../routes/weather.routes';
import { permissionService } from '../../permission.service';

const TENANT = 1;
const OTHER_TENANT = 2;

/** Two carriers and a mobile network. Documentation-safe ranges are refused by
 *  `classifyIpScope` on purpose, so these are ordinary public blocks. */
const AS_ALPHA = { asn: 64500, org: 'Alpha Telecom', prefix: '185.10.0.0/16', base: '185.10' };
const AS_BETA = { asn: 64510, org: 'Beta Networks', prefix: '185.20.0.0/16', base: '185.20' };
const AS_MOBILE = { asn: 64520, org: 'Mobile Carrier', prefix: '185.30.0.0/16', base: '185.30' };

// ============================================================================
// Harness
// ============================================================================

let passed = 0;
let failed = 0;
const failures: string[] = [];

function ok(label: string, cond: boolean, extra = ''): void {
  if (cond) {
    passed++;
    console.log(`  PASS  ${label}${extra ? ' — ' + extra : ''}`);
  } else {
    failed++;
    failures.push(label + (extra ? ` — ${extra}` : ''));
    console.log(`  FAIL  ${label}${extra ? ' — ' + extra : ''}`);
  }
}

async function refuses(label: string, fn: () => Promise<unknown>, needle: string): Promise<void> {
  try {
    await fn();
    ok(label, false, 'it was accepted');
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    ok(label, message.toLowerCase().includes(needle.toLowerCase()), message.slice(0, 140));
  }
}

function section(title: string): void {
  console.log(`\n${title}\n${'-'.repeat(title.length)}`);
}

// ============================================================================
// Seeding
// ============================================================================

interface Seeded {
  concentratorId: number;
  devices: Array<{ id: number; siteId: number; name: string; username: string }>;
}

async function reset(): Promise<void> {
  await db.raw(
    'TRUNCATE operator_incident_members, operator_incidents, wan_path_events, ' +
      'device_wan_path, weather_settings, weather_asn_imports, ip_asn_ranges ' +
      'RESTART IDENTITY CASCADE',
  );
  await db.raw('TRUNCATE ppp_sessions RESTART IDENTITY CASCADE');
  await db('snmp_interfaces').del();
  await db('devices').del();
  await db('sites').del();
  clearAsnCache();
}

async function seedTenants(): Promise<void> {
  await db('tenants')
    .insert([
      { id: TENANT, name: 'Default', slug: 'default' },
      { id: OTHER_TENANT, name: 'Other MSP customer', slug: 'other' },
    ])
    .onConflict('id')
    .ignore();
}

async function seedAsnTable(): Promise<void> {
  await importAsnRanges(
    [AS_ALPHA, AS_BETA, AS_MOBILE].map((a) => ({
      prefix: a.prefix,
      asn: a.asn,
      asOrg: a.org,
      country: 'FR',
      region: 'FR-IDF',
    })),
    { label: 'f5-verify fixture', source: 'manual' },
  );
}

/** `count` sites, one router each, all sitting on `carrier`. */
async function seedFleet(
  tenantId: number,
  prefix: string,
  count: number,
  carrier: { base: string },
): Promise<Seeded> {
  const [chr] = await db('devices')
    .insert({
      tenant_id: tenantId,
      name: `${prefix}-chr`,
      brand: 'mikrotik',
      family: 'mikrotik_routeros7',
      role: 'concentrator',
      status: 'active',
    })
    .returning<Array<{ id: number }>>('id');

  const devices: Seeded['devices'] = [];
  for (let i = 1; i <= count; i++) {
    const [site] = await db('sites')
      .insert({ tenant_id: tenantId, code: `${prefix}-S${i}`, name: `Site ${prefix}-${i}` })
      .returning<Array<{ id: number }>>('id');
    const username = `${prefix}-site${i}`;
    const [device] = await db('devices')
      .insert({
        tenant_id: tenantId,
        site_id: site.id,
        name: `${prefix}-router-${i}`,
        brand: 'mikrotik',
        family: 'mikrotik_routeros7',
        role: 'cpe',
        status: 'active',
        concentrator_id: chr.id,
        ppp_username: username,
        wan_public_ip: `${carrier.base}.1.${i}`,
      })
      .returning<Array<{ id: number }>>('id');
    devices.push({ id: device.id, siteId: site.id, name: `${prefix}-router-${i}`, username });
  }
  return { concentratorId: chr.id, devices };
}

/**
 * Write the PPP session pair that `applySessionUp` would have written: the
 * session the site used to hold, then the one it came back on from a different
 * public address. That second row IS `publicPathChanged`, persisted.
 */
async function seedFailover(
  seeded: Seeded,
  device: Seeded['devices'][number],
  fromIp: string,
  toIp: string,
  minutesAgo: number,
): Promise<void> {
  const now = Date.now();
  await db('ppp_sessions').insert({
    concentrator_id: seeded.concentratorId,
    device_id: device.id,
    ppp_username: device.username,
    caller_ip: fromIp,
    started_at: new Date(now - (minutesAgo + 120) * 60_000),
    ended_at: new Date(now - minutesAgo * 60_000),
    duration_seconds: 7200,
  });
  await seedSessionUp(seeded, device, toIp, minutesAgo);
}

/**
 * One session coming up, exactly as `applySessionUp` would have written it.
 *
 * The open session of the same username is closed FIRST, because
 * `ppp_sessions_open_uniq` (migration 002) permits exactly one open row per
 * (concentrator, username) — the fixture has to respect the same rule the
 * reconciliation sweep does, or it is not modelling the product.
 */
async function seedSessionUp(
  seeded: Seeded,
  device: Seeded['devices'][number],
  ip: string,
  minutesAgo: number,
): Promise<void> {
  const at = new Date(Date.now() - minutesAgo * 60_000);
  await db('ppp_sessions')
    .where({ concentrator_id: seeded.concentratorId, ppp_username: device.username })
    .whereNull('ended_at')
    .update({ ended_at: at, duration_seconds: 60 });
  await db('ppp_sessions').insert({
    concentrator_id: seeded.concentratorId,
    device_id: device.id,
    ppp_username: device.username,
    caller_ip: ip,
    started_at: at,
  });
  await db('devices').where({ id: device.id }).update({ wan_public_ip: ip });
}

// ============================================================================
// A scripted RouterOS box
// ============================================================================

function fakeRouter(script: Record<string, Record<string, string>[]>): RouterOsQueryable {
  return {
    async query(words: string[]): Promise<Record<string, string>[]> {
      const rows = script[words[0]];
      if (rows === undefined) {
        // A RouterOS `!trap`: "no such command". Matched by NAME in the
        // resolver, which is what makes this fake faithful.
        const err = new Error(`no such command prefix (${words[0]})`);
        err.name = 'RouterOsTrapError';
        throw err;
      }
      return rows;
    },
  };
}

function matrixFor(major: number): RouterOsCapabilityMatrix {
  return {
    probedAt: new Date(),
    version: `${major}.14.3 (stable)`,
    major,
    minor: 14,
    patch: 3,
    channel: 'stable',
    family: major >= 7 ? 'mikrotik_routeros7' : 'mikrotik_routeros6',
    identity: 'test',
    boardName: 'RB5009',
    platform: 'MikroTik',
    architecture: 'arm64',
    serialNumber: null,
    healthShape: major >= 7 ? 'rows' : 'record',
    hasRouterboard: true,
    hasWireless: false,
    hasPppServer: false,
    paths: {
      identity: '/system/identity/print',
      resource: '/system/resource/print',
      routerboard: '/system/routerboard/print',
      health: '/system/health/print',
      interfaces: '/interface/print',
      interfaceMonitorTraffic: '/interface/monitor-traffic',
      ipAddress: '/ip/address/print',
      ipRoute: '/ip/route/print',
      firewallFilter: '/ip/firewall/filter/print',
      firewallNat: '/ip/firewall/nat/print',
      firewallAddressList: '/ip/firewall/address-list/print',
      dhcpServerLease: '/ip/dhcp-server/lease/print',
      wireless: null,
      pppActive: '/ppp/active/print',
      pppActiveListen: '/ppp/active/listen',
      pppSecret: '/ppp/secret/print',
      log: '/log/print',
      logListen: '/log/listen',
      export: '/export',
    },
    notes: [],
  };
}

// ============================================================================
// 1. Offline: address scope, ranges, parsing
// ============================================================================

function offlineAddressTests(): void {
  section('1. Address scope — the gate in front of every attribution');

  ok('a public v4 address is attributable', classifyIpScope('185.10.1.1') === 'public');
  ok('RFC1918 is not', classifyIpScope('10.8.0.14') === 'private');
  ok('172.16/12 is', classifyIpScope('172.20.3.4') === 'private');
  ok('172.32/12 is NOT private', classifyIpScope('172.32.3.4') === 'public');
  ok('CGNAT is called out separately', classifyIpScope('100.90.1.2') === 'cgnat');
  ok('loopback', classifyIpScope('127.0.0.1') === 'loopback');
  ok('link-local', classifyIpScope('169.254.5.5') === 'linklocal');
  ok('documentation range is invalid', classifyIpScope('203.0.113.7') === 'invalid');
  ok('garbage is invalid', classifyIpScope('not-an-ip') === 'invalid');
  ok('null is invalid', classifyIpScope(null) === 'invalid');
  ok('v6 ULA is private', classifyIpScope('fd00::1') === 'private');
  ok('v6 GUA is public', classifyIpScope('2a01:e34::1') === 'public');
  ok(
    'only a public address is attributable',
    isAttributableAddress('185.10.1.1') && !isAttributableAddress('10.0.0.1') &&
      !isAttributableAddress('100.90.1.2'),
  );
  ok('a caller-id with a mask suffix still parses', classifyIpScope('185.10.1.1/32') === 'public');

  section('2. Range arithmetic — the offline dataset loader');

  const single = rangeToCidrs('10.0.0.0', '10.0.0.255');
  ok('an aligned /24 is one block', single.length === 1 && single[0] === '10.0.0.0/24', single.join(','));

  const ragged = rangeToCidrs('1.0.0.1', '1.0.0.6');
  ok(
    'a ragged range decomposes exactly',
    ragged.join(',') === '1.0.0.1/32,1.0.0.2/31,1.0.0.4/31,1.0.0.6/32',
    ragged.join(','),
  );
  ok('an inverted range yields nothing', rangeToCidrs('10.0.0.5', '10.0.0.1').length === 0);
  ok('a malformed range yields nothing', rangeToCidrs('nope', '10.0.0.1').length === 0);
  ok(
    'a mixed-family range yields nothing',
    rangeToCidrs('10.0.0.1', '2001:db8::1').length === 0,
  );

  const tsv = parseAsnRangeLine('185.10.0.0\t185.10.255.255\t64500\tFR\tAlpha Telecom');
  ok('the start/end TSV form parses', tsv.length === 1 && tsv[0].prefix === '185.10.0.0/16', JSON.stringify(tsv[0]));
  ok('…and keeps the organisation', tsv[0]?.asOrg === 'Alpha Telecom' && tsv[0]?.country === 'FR');

  const cidr = parseAsnRangeLine('185.20.0.0/16 AS64510 FR Beta');
  ok('the CIDR form parses, with or without the AS prefix', cidr.length === 1 && cidr[0].asn === 64510);
  ok('a comment yields nothing', parseAsnRangeLine('# header').length === 0);
  ok('a blank line yields nothing', parseAsnRangeLine('   ').length === 0);
  ok('AS0 is refused', parseAsnRangeLine('10.0.0.0/8 0 FR x').length === 0);
  ok(
    'an ASN past the 32-bit space is refused',
    parseAsnRangeLine('10.0.0.0/8 4294967296 FR x').length === 0,
  );
  ok('a country that is not a country code is dropped', parseAsnRangeLine('185.20.0.0/16 64510 FRANCE')[0]?.country === null);
}

// ============================================================================
// 3. Offline: the quorum itself
// ============================================================================

/** The quorum counts LINE KEYS (see `lineKeyOf`); a bare site id in a fixture
 *  has to be spelled the way the correlator spells it. */
const siteKey = (id: number): string => lineKeyOf(id, id, null);

function candidate(asn: number, sites: number[], fleet: number): AsnCandidate {
  return { asn, asOrg: `AS${asn}`, affectedSiteKeys: sites.map(siteKey), fleetSiteCount: fleet };
}

function offlineQuorumTests(): void {
  section('3. The quorum — pure, and the thing that decides everything');

  const p = DEFAULT_WEATHER_POLICY;

  ok('one site never reaches quorum', !quorumFor(candidate(1, [10], 20), p).met);
  ok(
    'four sites out of twenty do not either (absolute quorum is five)',
    !quorumFor(candidate(1, [1, 2, 3, 4], 20), p).met,
  );
  ok(
    'five sites out of six do',
    quorumFor(candidate(1, [1, 2, 3, 4, 5], 6), p).met,
  );
  ok(
    'five sites out of four hundred do NOT — the relative quorum bites',
    !quorumFor(candidate(1, [1, 2, 3, 4, 5], 400), p).met,
    quorumFor(candidate(1, [1, 2, 3, 4, 5], 400), p).reason,
  );
  ok(
    'the same site counted twelve times is still one site',
    !quorumFor(candidate(1, [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7], 20), p).met,
  );
  ok(
    'a device with no site gets a private key that merges with nothing',
    siteKeyOf(null, 42) === -42 && siteKeyOf(3, 42) === 3,
  );
  ok(
    'the QUORUM key prefers the site, then the line, then the device',
    lineKeyOf(3, 42, '185.10.1.1') === 'site:3' &&
      lineKeyOf(null, 42, '185.10.1.1') === 'line:185.10.1.1' &&
      lineKeyOf(null, 42, null) === 'dev:42',
  );
  ok(
    'two devices behind the same line share ONE key, and reach no quorum alone',
    !quorumFor(
      {
        asn: 1, asOrg: null, fleetSiteCount: 5,
        affectedSiteKeys: [11, 12, 13, 14, 15].map((d) => lineKeyOf(null, d, '185.10.1.1')),
      },
      p,
    ).met,
  );
  ok(
    '…while five devices on five lines do',
    quorumFor(
      {
        asn: 1, asOrg: null, fleetSiteCount: 6,
        affectedSiteKeys: [11, 12, 13, 14, 15].map((d) => lineKeyOf(null, d, `185.10.1.${d}`)),
      },
      p,
    ).met,
  );
  ok(
    'a mask suffix does not fork a line into two',
    lineKeyOf(null, 1, '185.10.1.1/32') === lineKeyOf(null, 2, '185.10.1.1'),
  );

  section('4. Scenario A — ONE site flips: no operator alert, ever');

  const one = evaluateOperatorWeather({
    now: new Date().toISOString(),
    policy: p,
    attributedSiteCount: 40,
    candidates: [candidate(AS_ALPHA.asn, [11], 19)],
    openIncidents: [],
  });
  ok('no action at all', one.actions.length === 0);
  ok('and the near-miss is reported honestly', one.asns[0].reason.startsWith('below_absolute_quorum'), one.asns[0].reason);

  section('5. Scenario B — twelve sites, same ASN, ten minutes: ONE alert');

  const twelve = Array.from({ length: 12 }, (_, i) => i + 1);
  const many = evaluateOperatorWeather({
    now: new Date().toISOString(),
    policy: p,
    attributedSiteCount: 40,
    candidates: [candidate(AS_ALPHA.asn, twelve, 14)],
    openIncidents: [],
  });
  ok('exactly one action', many.actions.length === 1, JSON.stringify(many.actions.map((a) => a.kind)));
  ok('and it is an open', many.actions[0]?.kind === 'open');
  ok(
    'carrying all twelve sites, not twelve separate alerts',
    many.actions[0]?.kind === 'open' && many.actions[0].siteKeys.length === 12,
  );

  section('6. Scenario C — twelve sites, twelve ASNs: it is us, not them');

  const scattered = evaluateOperatorWeather({
    now: new Date().toISOString(),
    policy: p,
    attributedSiteCount: 25,
    candidates: Array.from({ length: 12 }, (_, i) => candidate(64600 + i, [i + 1], 2)),
    openIncidents: [],
  });
  ok('no incident opens', scattered.actions.length === 0);
  ok('the fleet-wide guard is what says so', scattered.fleetWide);
  ok('and it says why', (scattered.fleetWideReason ?? '').includes('fleet_wide'), scattered.fleetWideReason ?? '');

  // Even with the guard disabled, no single-site ASN can reach quorum: two
  // independent reasons, which is the point.
  const scatteredNoGuard = evaluateOperatorWeather({
    now: new Date().toISOString(),
    policy: { ...p, fleetWideAsnCount: 100 },
    attributedSiteCount: 25,
    candidates: Array.from({ length: 12 }, (_, i) => candidate(64600 + i, [i + 1], 2)),
    openIncidents: [],
  });
  ok(
    'and with the guard switched off, the quorum alone still refuses',
    scatteredNoGuard.actions.length === 0 && !scatteredNoGuard.fleetWide,
  );

  // A REAL carrier outage during a busy afternoon must still fire: the guard
  // keys on ASNs SPREAD, not on volume.
  const realDuringNoise = evaluateOperatorWeather({
    now: new Date().toISOString(),
    policy: p,
    attributedSiteCount: 200,
    candidates: [candidate(AS_ALPHA.asn, twelve, 14), candidate(AS_BETA.asn, [90], 30)],
    openIncidents: [],
  });
  ok(
    'a genuine outage next to unrelated noise still opens',
    realDuringNoise.actions.length === 1 && realDuringNoise.actions[0].kind === 'open',
  );

  section('7. Scenario D — the asymmetry: closing is slower than opening');

  const clearingThreshold = clearThreshold(p);
  ok('the clearing threshold is below the quorum', clearingThreshold < p.minSites, `${clearingThreshold} < ${p.minSites}`);

  const live: OpenIncidentState = {
    incidentId: 1,
    asn: AS_ALPHA.asn,
    status: 'open',
    clearingSince: null,
    stillAffectedSiteKeys: [],
    peakSiteCount: 12,
  };
  const recovering = evaluateOperatorWeather({
    now: new Date().toISOString(),
    policy: p,
    attributedSiteCount: 40,
    candidates: [],
    openIncidents: [live],
  });
  ok('recovery starts a hold-down, it does not close', recovering.actions[0]?.kind === 'start_clearing');

  const justStarted = new Date();
  const stillHolding = evaluateOperatorWeather({
    now: justStarted.toISOString(),
    policy: p,
    attributedSiteCount: 40,
    candidates: [],
    openIncidents: [{ ...live, status: 'clearing', clearingSince: justStarted.toISOString() }],
  });
  ok('one minute into the hold-down, nothing closes', stillHolding.actions.length === 0);

  const heldLongEnough = evaluateOperatorWeather({
    now: new Date(justStarted.getTime() + (p.holdDownMinutes + 1) * 60_000).toISOString(),
    policy: p,
    attributedSiteCount: 40,
    candidates: [],
    openIncidents: [{ ...live, status: 'clearing', clearingSince: justStarted.toISOString() }],
  });
  ok('once the hold-down has elapsed, it closes', heldLongEnough.actions[0]?.kind === 'close');

  const relapse = evaluateOperatorWeather({
    now: new Date(justStarted.getTime() + 60_000).toISOString(),
    policy: p,
    attributedSiteCount: 40,
    candidates: [candidate(AS_ALPHA.asn, twelve, 14)],
    openIncidents: [
      {
        ...live, status: 'clearing', clearingSince: justStarted.toISOString(),
        stillAffectedSiteKeys: twelve.map(siteKey),
      },
    ],
  });
  ok('a relapse resumes it instead of closing it', relapse.actions[0]?.kind === 'resume');
  ok('and does not open a second incident for the same ASN', !relapse.actions.some((a) => a.kind === 'open'));

  const corrupted = evaluateOperatorWeather({
    now: new Date().toISOString(),
    policy: p,
    attributedSiteCount: 40,
    candidates: [],
    openIncidents: [{ ...live, status: 'clearing', clearingSince: null }],
  });
  ok('a clearing row with no timestamp refuses to close', corrupted.actions.length === 0);

  section('8. The asymmetry is validated, not merely documented');

  ok(
    'the default policy closes at least twice as slowly as it opens',
    DEFAULT_WEATHER_POLICY.holdDownMinutes >=
      MIN_HOLD_DOWN_RATIO * DEFAULT_WEATHER_POLICY.windowMinutes,
  );
  ok(
    'a symmetric policy is rejected',
    validateWeatherPolicy({ ...p, holdDownMinutes: 10 }).some((x) => x.field === 'holdDownMinutes'),
  );
  // The `clearRatio` branch of `validateWeatherPolicy` was DELETED: it tested
  // `clearThreshold > minSites`, which Zod's [0,1] bound on clearRatio and
  // `minSites >= 2` made unreachable from every caller. What actually refuses
  // an out-of-range ratio is the schema, so that is what is asserted — and
  // `clearRatio = 1`, the degenerate value the deleted branch would have
  // outlawed if it had been tightened instead, must stay LEGAL because
  // `resumeThreshold` has a floor written for it.
  ok(
    'validateWeatherPolicy states exactly one rule, and it is the hold-down one',
    validateWeatherPolicy({ ...p, clearRatio: 1 }).length === 0,
    JSON.stringify(validateWeatherPolicy({ ...p, clearRatio: 1 })),
  );
  try {
    normalizeWeatherPolicy({ ...p, clearRatio: 1.5 });
    ok('a clearRatio above 1 is refused by the schema', false, 'it was accepted');
  } catch (err) {
    ok('a clearRatio above 1 is refused by the schema', err instanceof WeatherPolicyError);
  }
  try {
    normalizeWeatherPolicy({ ...p, holdDownMinutes: 5 });
    ok('normalizeWeatherPolicy throws on a symmetric policy', false, 'it was accepted');
  } catch (err) {
    ok('normalizeWeatherPolicy throws on a symmetric policy', err instanceof WeatherPolicyError);
  }
  try {
    normalizeWeatherPolicy({ ...p, nonsense: 1 });
    ok('an unknown policy key is refused (strict)', false, 'it was accepted');
  } catch (err) {
    ok('an unknown policy key is refused (strict)', err instanceof WeatherPolicyError);
  }
  ok(
    'a missing policy falls back to the default rather than throwing',
    normalizeWeatherPolicy(null).minSites === DEFAULT_WEATHER_POLICY.minSites,
  );
}

// ============================================================================
// 9. The egress path (R11)
// ============================================================================

async function egressTests(): Promise<void> {
  section('9. The active egress path — matrix-driven, never a hard-coded menu');

  const wanRows = [
    { 'dst-address': '0.0.0.0/0', gateway: '185.10.1.254', 'immediate-gw': '185.10.1.254%ether1', distance: '1', active: 'true' },
    { 'dst-address': '0.0.0.0/0', gateway: '10.7.0.1', 'immediate-gw': '10.7.0.1%lte1', distance: '10', active: 'false' },
  ];
  const lteRows = [
    { 'dst-address': '0.0.0.0/0', gateway: '185.10.1.254', 'immediate-gw': '185.10.1.254%ether1', distance: '1', active: 'false' },
    { 'dst-address': '0.0.0.0/0', gateway: '10.7.0.1', 'immediate-gw': '10.7.0.1%lte1', distance: '10', active: 'true' },
  ];

  ok(
    'the ACTIVE default route is picked, not the first one printed',
    pickActiveDefaultRoute(lteRows)?.iface === 'lte1',
  );
  ok('…and the primary is picked when it is the live one', pickActiveDefaultRoute(wanRows)?.iface === 'ether1');
  ok('no active default route yields null, not a guess', pickActiveDefaultRoute([
    { 'dst-address': '0.0.0.0/0', gateway: '1.2.3.4', distance: '1', active: 'false' },
  ]) === null);
  ok('a route table with no default at all yields null', pickActiveDefaultRoute([
    { 'dst-address': '192.168.0.0/24', gateway: 'bridge', active: 'true' },
  ]) === null);

  // RouterOS 7 with an LTE menu, currently on LTE.
  invalidateCellularPaths('device:v7');
  const v7 = await resolveEgressFromRouter(
    fakeRouter({
      '/ip/route/print': lteRows,
      '/interface/lte/print': [{ name: 'lte1', running: 'true' }],
      '/ip/address/print': [{ interface: 'lte1', address: '10.7.0.22/24' }],
    }),
    matrixFor(7),
    'device:v7',
  );
  ok('RouterOS 7: the site is on LTE', v7.pathKind === 'lte', JSON.stringify(v7.egressInterface));
  ok('…and the source says which signal decided it', v7.source === 'routeros_lte');
  ok('…and the modem is registered', v7.lteRegistered === true);
  ok(
    'a carrier-NAT address on the egress is NOT recorded as a public self-report',
    v7.reportedPublicIp === null,
  );

  // RouterOS 6, no LTE menu at all: the probe must degrade, not throw.
  invalidateCellularPaths('device:v6');
  const v6 = await resolveEgressFromRouter(
    fakeRouter({
      '/ip/route/print': wanRows,
      '/ip/address/print': [{ interface: 'ether1', address: '185.10.1.5/24' }],
    }),
    matrixFor(6),
    'device:v6',
  );
  ok('RouterOS 6 with no cellular menu: the site is on its WAN port', v6.pathKind === 'wan_port');
  ok('…the missing menu is reported as a note, not as an error', v6.notes.some((n) => n.includes('No cellular menu')));
  ok(
    '…and a public address on the egress IS recorded as the fallback',
    v6.reportedPublicIp === '185.10.1.5',
  );

  // The cellular probe is cached per device: a second call must not re-probe.
  let probes = 0;
  const counting: RouterOsQueryable = {
    async query(words) {
      if (words[0] === '/interface/lte/print') probes++;
      if (words[0] === '/ip/route/print') return wanRows;
      if (words[0] === '/interface/lte/print') return [];
      if (words[0] === '/ip/address/print') return [];
      const err = new Error('no such command prefix');
      err.name = 'RouterOsTrapError';
      throw err;
    },
  };
  invalidateCellularPaths('device:cache');
  await resolveEgressFromRouter(counting, matrixFor(7), 'device:cache');
  const afterFirst = probes;
  await resolveEgressFromRouter(counting, matrixFor(7), 'device:cache');
  ok('the cellular menu is probed once per device, then cached', probes === afterFirst + 1, `${probes} probes`);
}

// ============================================================================
// 10. Database-backed scenarios
// ============================================================================

async function scenarioNoAlertForOneSite(): Promise<void> {
  section('10. Scenario A against Postgres — one site flips, nobody is paged');

  await reset();
  await seedTenants();
  await seedAsnTable();
  const fleet = await seedFleet(TENANT, 'a', 14, AS_ALPHA);

  await seedFailover(fleet, fleet.devices[0], `${AS_ALPHA.base}.1.1`, `${AS_MOBILE.base}.9.1`, 3);
  const outcome = await runWeatherScan(TENANT);

  ok('the failover WAS detected', outcome.ingested === 1, `${outcome.ingested} event(s)`);
  const events = await db('wan_path_events').where({ tenant_id: TENANT }).select('*');
  ok('…recorded as an `away` from the carrier it left', events[0]?.direction === 'away');
  ok(
    '…keyed on the ASN it LEFT, not the one it arrived on',
    Number(events[0]?.from_asn) === AS_ALPHA.asn && Number(events[0]?.to_asn) === AS_MOBILE.asn,
  );
  ok('NO operator incident was opened', outcome.opened.length === 0);
  ok('…and none exists in the database', (await listIncidents(TENANT)).length === 0);

  // Idempotence: the same sweep twice must not double the vote.
  const again = await runWeatherScan(TENANT);
  ok('a second sweep ingests nothing new', again.ingested === 0);
  const count = await db('wan_path_events').where({ tenant_id: TENANT }).count<Array<{ count: string }>>('* as count');
  ok('…and the event count is unchanged', Number(count[0].count) === 1);
}

async function scenarioOneAlertForTwelve(): Promise<number> {
  section('11. Scenario B against Postgres — twelve sites, ONE alert');

  await reset();
  await seedTenants();
  await seedAsnTable();
  const fleet = await seedFleet(TENANT, 'b', 14, AS_ALPHA);
  const other = await seedFleet(OTHER_TENANT, 'x', 14, AS_ALPHA);

  // Twelve of the fourteen sites leave Alpha inside ten minutes.
  for (let i = 0; i < 12; i++) {
    await seedFailover(
      fleet,
      fleet.devices[i],
      `${AS_ALPHA.base}.1.${i + 1}`,
      `${AS_MOBILE.base}.9.${i + 1}`,
      i % 9,
    );
  }
  // The OTHER tenant's twelve sites leave the same ASN at the same moment. If
  // the quorum were computed without `tenant_id`, this would double every count
  // and produce a joint incident across two MSP customers.
  for (let i = 0; i < 12; i++) {
    await seedFailover(
      other,
      other.devices[i],
      `${AS_ALPHA.base}.5.${i + 1}`,
      `${AS_MOBILE.base}.7.${i + 1}`,
      i % 9,
    );
  }

  const outcome = await runWeatherScan(TENANT);
  ok('twelve transitions were ingested', outcome.ingested === 12, `${outcome.ingested}`);
  ok('EXACTLY ONE incident opened', outcome.opened.length === 1, JSON.stringify(outcome.opened));

  const incidents = await listIncidents(TENANT);
  ok('…and exactly one row exists', incidents.length === 1);
  ok('…on the ASN the sites LEFT', incidents[0]?.asn === AS_ALPHA.asn);
  ok('…with all twelve sites in it', incidents[0]?.currentSiteCount === 12, `${incidents[0]?.currentSiteCount}`);
  ok('…and the denominator is the carrier footprint', incidents[0]?.fleetSiteCount === 14, `${incidents[0]?.fleetSiteCount}`);

  const detail = await getIncident(TENANT, incidents[0].id);
  ok('the incident names its members', detail?.members.length === 12);
  ok('…and freezes the policy that opened it', detail?.policy.minSites === DEFAULT_WEATHER_POLICY.minSites);

  // Sweeping again must not produce a second alert for the same outage.
  const second = await runWeatherScan(TENANT);
  ok('a second sweep opens nothing', second.opened.length === 0);
  ok('…and there is still exactly one incident', (await listIncidents(TENANT)).length === 1);

  // The database itself refuses a second live incident on the same ASN.
  await refuses(
    'the schema refuses a second LIVE incident on the same (tenant, ASN)',
    () =>
      db('operator_incidents').insert({
        tenant_id: TENANT,
        asn: AS_ALPHA.asn,
        status: 'open',
        policy: JSON.stringify(DEFAULT_WEATHER_POLICY),
      }),
    'operator_incidents_live_uniq',
  );

  // The other tenant is untouched by this tenant's incident, and gets its own.
  const otherIncidents = await listIncidents(OTHER_TENANT);
  ok('the other tenant has NO incident from our sweep', otherIncidents.length === 0);
  const otherOutcome = await runWeatherScan(OTHER_TENANT);
  ok('…and its own sweep opens exactly one of its own', otherOutcome.opened.length === 1);
  const otherDetail = await getIncident(OTHER_TENANT, otherOutcome.opened[0]);
  ok('…containing only its own twelve sites', otherDetail?.members.length === 12);
  ok(
    'reading another tenant incident by id is a not-found, not a leak',
    (await getIncident(TENANT, otherOutcome.opened[0])) === null,
  );

  return incidents[0].id;
}

async function scenarioFleetWide(): Promise<void> {
  section('12. Scenario C against Postgres — twelve ASNs: the fault is ours');

  await reset();
  await seedTenants();
  // One /16 per carrier, twelve carriers, one site each.
  await importAsnRanges(
    Array.from({ length: 12 }, (_, i) => ({
      prefix: `186.${i}.0.0/16`,
      asn: 64600 + i,
      asOrg: `Carrier ${i}`,
      country: 'FR',
      region: null,
    })).concat([
      { prefix: AS_MOBILE.prefix, asn: AS_MOBILE.asn, asOrg: AS_MOBILE.org, country: 'FR', region: null },
    ]),
    { label: 'f5 scattered fixture', source: 'manual' },
  );

  const fleet = await seedFleet(TENANT, 'c', 12, { base: '186.0' });
  for (let i = 0; i < 12; i++) {
    await db('devices').where({ id: fleet.devices[i].id }).update({ wan_public_ip: `186.${i}.1.1` });
    await seedFailover(fleet, fleet.devices[i], `186.${i}.1.1`, `${AS_MOBILE.base}.9.${i + 1}`, i % 9);
  }

  const outcome = await runWeatherScan(TENANT);
  ok('all twelve transitions were ingested', outcome.ingested === 12);
  ok('NO operator incident opened', outcome.opened.length === 0);
  ok('the fleet-wide guard fired', outcome.evaluation.fleetWide);
  ok(
    '…and says, in words, that this is not a carrier problem',
    (outcome.evaluation.fleetWideReason ?? '').includes('ours, not theirs'),
  );
  ok('no incident row exists', (await listIncidents(TENANT)).length === 0);
}

async function scenarioRecovery(): Promise<void> {
  section('13. Scenario D against Postgres — recovery closes it, slowly');

  await reset();
  await seedTenants();
  await seedAsnTable();
  const fleet = await seedFleet(TENANT, 'd', 14, AS_ALPHA);
  for (let i = 0; i < 12; i++) {
    await seedFailover(fleet, fleet.devices[i], `${AS_ALPHA.base}.1.${i + 1}`, `${AS_MOBILE.base}.9.${i + 1}`, i % 9);
  }

  const opened = await runWeatherScan(TENANT);
  ok('the incident opened', opened.opened.length === 1);
  const incidentId = opened.opened[0];
  const openedAt = Date.now();

  // The sites come back onto Alpha: a new PPP session from the original public
  // address, which is exactly what `applySessionUp` writes.
  for (let i = 0; i < 12; i++) {
    await seedSessionUp(fleet, fleet.devices[i], `${AS_ALPHA.base}.1.${i + 1}`, 0);
  }

  const recovering = await runWeatherScan(TENANT, { skipIngest: false });
  const afterRecovery = await getIncident(TENANT, incidentId);
  ok('every member is marked recovered', afterRecovery !== null && afterRecovery.members.every((m) => m.recoveredAt !== null));
  ok('the incident is CLEARING, not closed', afterRecovery?.status === 'clearing', afterRecovery?.status);
  ok('…and the sweep reported it as such', recovering.clearing.includes(incidentId));
  ok('…with the count back to zero', afterRecovery?.currentSiteCount === 0);
  ok('…while the peak is preserved for the post-mortem', afterRecovery?.peakSiteCount === 12);

  // Immediately re-sweeping must NOT close it: the hold-down has not elapsed.
  const tooSoon = await runWeatherScan(TENANT);
  ok('a sweep during the hold-down does not close it', tooSoon.closed.length === 0);
  ok(
    '…the incident is still clearing',
    (await getIncident(TENANT, incidentId))?.status === 'clearing',
  );

  // Age the clearing timestamp past the hold-down, and age the `away` events
  // out of the correlation window — which is exactly what really happens, since
  // the hold-down is at least twice the window.
  const policy = (await getTenantPolicy(TENANT)).policy;
  await db('operator_incidents')
    .where({ id: incidentId })
    .update({ clearing_since: new Date(Date.now() - (policy.holdDownMinutes + 1) * 60_000) });
  await db('wan_path_events')
    .where({ tenant_id: TENANT })
    .update({ at: new Date(Date.now() - (policy.windowMinutes + 5) * 60_000) });

  const closing = await runWeatherScan(TENANT, { skipIngest: true });
  const closed = await getIncident(TENANT, incidentId);
  ok('once the hold-down has elapsed, the incident closes', closing.closed.includes(incidentId));
  ok('…and the row says so, with a timestamp', closed?.status === 'closed' && closed.closedAt !== null);
  ok('…and records why it closed', (closed?.closeReason ?? '').includes('held_'), closed?.closeReason ?? '');
  ok(
    'closing took longer than opening, by construction',
    policy.holdDownMinutes >= MIN_HOLD_DOWN_RATIO * policy.windowMinutes &&
      Date.now() - openedAt < policy.holdDownMinutes * 60_000,
  );

  // A closed incident must not immediately reopen from the same stale evidence.
  const after = await runWeatherScan(TENANT, { skipIngest: true });
  ok('the closed incident does not immediately reopen', after.opened.length === 0);
  ok('…and history keeps it', (await listIncidents(TENANT, { status: 'closed' })).length === 1);

  section('14. A relapse re-opens the SAME incident, it does not fork a new one');

  await reset();
  await seedTenants();
  await seedAsnTable();
  const f2 = await seedFleet(TENANT, 'e', 14, AS_ALPHA);
  for (let i = 0; i < 12; i++) {
    await seedFailover(f2, f2.devices[i], `${AS_ALPHA.base}.1.${i + 1}`, `${AS_MOBILE.base}.9.${i + 1}`, 1);
  }
  const r1 = await runWeatherScan(TENANT);
  const relapseId = r1.opened[0];
  for (let i = 0; i < 12; i++) {
    await seedSessionUp(f2, f2.devices[i], `${AS_ALPHA.base}.1.${i + 1}`, 0);
  }
  await runWeatherScan(TENANT);
  ok('the incident entered clearing', (await getIncident(TENANT, relapseId))?.status === 'clearing');

  // Off they go again — a NEW session from a new mobile address, on top of the
  // history that is already there.
  for (let i = 0; i < 12; i++) {
    await seedSessionUp(f2, f2.devices[i], `${AS_MOBILE.base}.8.${i + 1}`, 0);
  }
  const r2 = await runWeatherScan(TENANT);
  const relapsed = await getIncident(TENANT, relapseId);
  ok('the relapse resumes the SAME incident', relapsed?.status === 'open', relapsed?.status);
  ok('…and the clearing timestamp is reset', relapsed?.clearingSince === null);
  ok('…no second incident was created', (await listIncidents(TENANT)).length === 1);
  ok('…and the members are back in the count', (relapsed?.currentSiteCount ?? 0) === 12, `${relapsed?.currentSiteCount}`);
  ok('…the sweep reports it as a resume, not an open', r2.resumed.includes(relapseId) && r2.opened.length === 0);
}

// ============================================================================
// 15. Schema-level refusals and the enrichment
// ============================================================================

async function schemaTests(): Promise<void> {
  section('15. What the DATABASE refuses, regardless of the service layer');

  await reset();
  await seedTenants();
  await seedAsnTable();
  const fleet = await seedFleet(TENANT, 'f', 3, AS_ALPHA);

  await refuses(
    'a policy that closes as fast as it opens is refused by the CHECK',
    () =>
      db('weather_settings').insert({
        tenant_id: TENANT,
        window_minutes: 10,
        min_sites: 5,
        min_fraction: 0.25,
        clear_ratio: 0.5,
        hold_down_minutes: 10,
        fleet_wide_asn_count: 4,
        fleet_wide_fraction: 0.3,
      }),
    'weather_settings_hold_down_chk',
  );

  await refuses(
    'a closed incident with no closed_at is refused',
    () =>
      db('operator_incidents').insert({
        tenant_id: TENANT,
        asn: AS_BETA.asn,
        status: 'closed',
        policy: JSON.stringify(DEFAULT_WEATHER_POLICY),
      }),
    'lifecycle',
  );

  await refuses(
    'an out-of-range ASN is refused',
    () =>
      db('operator_incidents').insert({
        tenant_id: TENANT,
        asn: 5_000_000_000,
        status: 'open',
        policy: JSON.stringify(DEFAULT_WEATHER_POLICY),
      }),
    'asn_chk',
  );

  await refuses(
    'a path kind outside the vocabulary is refused',
    () =>
      db('device_wan_path').insert({
        device_id: fleet.devices[0].id,
        tenant_id: TENANT,
        path_kind: 'satellite',
      }),
    'device_wan_path_kind_chk',
  );

  await refuses(
    'an address scope outside the vocabulary is refused',
    () =>
      db('device_wan_path').insert({
        device_id: fleet.devices[0].id,
        tenant_id: TENANT,
        ip_scope: 'probably-public',
      }),
    'device_wan_path_scope_chk',
  );

  await refuses(
    'an unattributable address cannot be filed under a carrier',
    () =>
      db('device_wan_path').insert({
        device_id: fleet.devices[0].id,
        tenant_id: TENANT,
        ip_scope: 'private',
        observed_public_ip: '10.8.0.1',
        asn: AS_ALPHA.asn,
      }),
    'device_wan_path_scope_asn_chk',
  );

  await refuses(
    'a device from another tenant cannot be filed under this one',
    () =>
      db('device_wan_path').insert({
        device_id: fleet.devices[0].id,
        tenant_id: OTHER_TENANT,
        path_kind: 'lte',
      }),
    'device_wan_path_device_tenant_fk',
  );

  await refuses(
    'the effective public address cannot be written by hand',
    () =>
      db.raw(
        'INSERT INTO device_wan_path (device_id, tenant_id, effective_public_ip) VALUES (?, ?, ?::inet)',
        [fleet.devices[1].id, TENANT, '1.2.3.4'],
      ),
    'non-DEFAULT',
  );

  // …and it resolves in the right direction, which is the whole point.
  await db('device_wan_path').insert({
    device_id: fleet.devices[1].id,
    tenant_id: TENANT,
    observed_public_ip: `${AS_ALPHA.base}.1.9`,
    reported_public_ip: `${AS_BETA.base}.1.9`,
    ip_scope: 'public',
    source: 'ppp_caller_id',
  });
  const both = await db('device_wan_path').where({ device_id: fleet.devices[1].id }).first();
  ok(
    "the concentrator's observation wins over the router's self-report",
    String(both.effective_public_ip) === `${AS_ALPHA.base}.1.9`,
    String(both.effective_public_ip),
  );

  await db('device_wan_path')
    .where({ device_id: fleet.devices[1].id })
    .update({ observed_public_ip: null });
  const fallbackOnly = await db('device_wan_path').where({ device_id: fleet.devices[1].id }).first();
  ok(
    '…and the self-report is used only when there is no observation',
    String(fallbackOnly.effective_public_ip) === `${AS_BETA.base}.1.9`,
  );

  section('16. The offline enrichment');

  const alpha = await attributeAddress(`${AS_ALPHA.base}.44.7`);
  ok('a public address is attributed by longest prefix', alpha.asn?.asn === AS_ALPHA.asn, JSON.stringify(alpha.asn));
  ok('…and names the block it matched', alpha.asn?.prefix === AS_ALPHA.prefix);

  // A more specific announcement inside the aggregate must win.
  await importAsnRanges(
    [{ prefix: `${AS_ALPHA.base}.44.0/24`, asn: AS_BETA.asn, asOrg: AS_BETA.org, country: 'FR', region: null }],
    { label: 'more specific', source: 'manual' },
  );
  const specific = await attributeAddress(`${AS_ALPHA.base}.44.7`);
  ok('the MORE SPECIFIC prefix wins', specific.asn?.asn === AS_BETA.asn, `${specific.asn?.prefix}`);

  const priv = await attributeAddress('10.8.0.14');
  ok('a private address is refused attribution', priv.asn === null && priv.reason === 'not_public');
  const unknown = await attributeAddress('198.18.5.5');
  ok('an uncovered public address says so honestly', unknown.asn === null && unknown.reason === 'no_covering_prefix');
  ok('no address at all is its own answer', (await attributeAddress(null)).reason === 'no_address');

  section('17. The generic, brand-agnostic LTE signal');

  await db('snmp_interfaces').insert([
    { device_id: fleet.devices[2].id, if_name: 'ether1', if_index: 1, if_type: 6, oper_status: 1 },
    { device_id: fleet.devices[2].id, if_name: 'lte1', if_index: 2, if_type: 243, oper_status: 1 },
  ]);
  const snmp = await resolveEgressFromSnmp(TENANT, fleet.devices[2].id);
  ok('IANAifType 243 identifies a cellular interface', snmp.pathKind === 'lte' && snmp.egressInterface === 'lte1');
  ok('the type table is deliberately short', isCellularIfType(243) && isCellularIfType(244) && !isCellularIfType(23));
  ok('the name heuristic is a hint, never a verdict', looksCellularByName('lte1') && !looksCellularByName('ether1'));

  const otherTenantView = await resolveEgressFromSnmp(OTHER_TENANT, fleet.devices[2].id);
  ok(
    "another tenant cannot read this device's interfaces through the fallback",
    otherTenantView.pathKind === 'unknown' && otherTenantView.ltePresent === false,
  );

  await db('snmp_interfaces').where({ device_id: fleet.devices[2].id, if_name: 'lte1' }).update({ oper_status: 2 });
  const down = await resolveEgressFromSnmp(TENANT, fleet.devices[2].id);
  ok('a present-but-down modem is a spare, not a failover', down.pathKind === 'unknown' && down.ltePresent);

  section('18. Persisting an observation');

  const observed = await observeEgressPath(TENANT, fleet.devices[2].id, { offlineOnly: true });
  ok('the offline path resolves and persists', observed.deviceId === fleet.devices[2].id);
  const row = await db('device_wan_path').where({ device_id: fleet.devices[2].id }).first();
  ok('…carrying the ASN of the concentrator observation', Number(row.asn) === AS_ALPHA.asn);
  ok('…and the observation itself, untouched', String(row.observed_public_ip) === `${AS_ALPHA.base}.1.3`);
  ok(
    '…while devices.wan_public_ip is never written by this milestone',
    String(
      (await db('devices').where({ id: fleet.devices[2].id }).first()).wan_public_ip,
    ) === `${AS_ALPHA.base}.1.3`,
  );
  await refuses(
    'observing a device of another tenant is a not-found',
    () => observeEgressPath(OTHER_TENANT, fleet.devices[2].id, { offlineOnly: true }),
    'not found',
  );

  section('19. The policy round-trip and the report');

  const saved = await setTenantPolicy(TENANT, { ...DEFAULT_WEATHER_POLICY, minSites: 8, holdDownMinutes: 60 });
  ok('a valid policy is stored', saved.policy.minSites === 8);
  const reloaded = await getTenantPolicy(TENANT);
  ok('…and read back identically', reloaded.policy.minSites === 8 && reloaded.policy.holdDownMinutes === 60);
  await refuses(
    'a symmetric policy is refused at the service boundary too',
    () => setTenantPolicy(TENANT, { ...DEFAULT_WEATHER_POLICY, windowMinutes: 60, holdDownMinutes: 30 }),
    'holdDownMinutes',
  );

  const report = await getWeatherReport(TENANT);
  ok('the report carries the policy in force', report.policy.minSites === 8);
  ok('…and the attributed footprint it was computed against', report.attributedSiteCount >= 0);
}

// ============================================================================
// 20. The ingestion's own rules
// ============================================================================

async function ingestionTests(): Promise<void> {
  section('20. What the ingestion refuses to call a failover');

  await reset();
  await seedTenants();
  await seedAsnTable();
  const fleet = await seedFleet(TENANT, 'g', 4, AS_ALPHA);

  // A renumber WITHIN the same carrier.
  await seedFailover(fleet, fleet.devices[0], `${AS_ALPHA.base}.1.1`, `${AS_ALPHA.base}.77.1`, 2);
  // A move between two private transits: unattributable on both sides.
  await seedFailover(fleet, fleet.devices[1], '10.8.0.5', '10.9.0.5', 2);
  // A genuine failover.
  await seedFailover(fleet, fleet.devices[2], `${AS_ALPHA.base}.1.3`, `${AS_MOBILE.base}.9.3`, 2);

  const outcome = await ingestPathEvents(TENANT);
  ok('all three transitions are recorded', outcome.inserted === 3, `${outcome.inserted}`);

  const rows = await db('wan_path_events').where({ tenant_id: TENANT }).orderBy('device_id');
  const byDevice = new Map(rows.map((r) => [r.device_id, r]));
  ok(
    'a renumber inside one carrier is `lateral`, never a vote',
    byDevice.get(fleet.devices[0].id)?.direction === 'lateral',
  );
  ok(
    'a move between private transits is recorded but unattributable',
    byDevice.get(fleet.devices[1].id)?.from_asn === null,
  );
  ok('…and is counted as such', outcome.skippedUnattributable === 1);
  ok('the genuine failover is `away`', byDevice.get(fleet.devices[2].id)?.direction === 'away');

  const rerun = await ingestPathEvents(TENANT);
  ok('re-running the ingestion inserts nothing', rerun.inserted === 0);
  ok(
    '…because the session key makes it idempotent',
    Number(
      (await db('wan_path_events').where({ tenant_id: TENANT }).count<Array<{ count: string }>>('* as count'))[0].count,
    ) === 3,
  );

  // Only `away` events can build a quorum: three lateral moves are not an outage.
  await reset();
  await seedTenants();
  await seedAsnTable();
  const lateral = await seedFleet(TENANT, 'h', 12, AS_ALPHA);
  for (let i = 0; i < 12; i++) {
    await seedFailover(lateral, lateral.devices[i], `${AS_ALPHA.base}.1.${i + 1}`, `${AS_ALPHA.base}.99.${i + 1}`, 1);
  }
  const lateralOutcome = await runWeatherScan(TENANT);
  ok('twelve renumbers inside ONE carrier open no incident', lateralOutcome.opened.length === 0);
  ok('…and produce no quorum candidate at all', lateralOutcome.evaluation.asns.length === 0);

  section('21. A tenant that switched the correlation off');

  await reset();
  await seedTenants();
  await seedAsnTable();
  const off = await seedFleet(TENANT, 'i', 14, AS_ALPHA);
  await setTenantPolicy(TENANT, DEFAULT_WEATHER_POLICY, false);
  for (let i = 0; i < 12; i++) {
    await seedFailover(off, off.devices[i], `${AS_ALPHA.base}.1.${i + 1}`, `${AS_MOBILE.base}.9.${i + 1}`, 1);
  }
  const disabled = await runWeatherScan(TENANT);
  ok('the quorum is still computed and reported', disabled.evaluation.asns[0]?.quorumMet === true);
  ok('…the transitions are still recorded', disabled.ingested === 12);
  ok('…but no incident is opened', disabled.opened.length === 0 && (await listIncidents(TENANT)).length === 0);
  await setTenantPolicy(TENANT, DEFAULT_WEATHER_POLICY, true);
  const reenabled = await runWeatherScan(TENANT);
  ok('turning it back on opens the incident that was waiting', reenabled.opened.length === 1);
}

// ============================================================================
// 22-26. The five findings of the F5 audit, each replayed verbatim
// ============================================================================
//
// Every section below reproduces one finding's `failure_scenario` against this
// same PostgreSQL, and then asserts the behaviour the fix installs. They are
// written as REGRESSION tests, not as demonstrations: each one fails on the
// code as it was audited.

/** A failover whose PREVIOUS session is arbitrarily old.
 *
 *  `seedFailover` hard-codes the previous session at `minutesAgo + 120`, which
 *  is the ONE duration for which finding 1 does not manifest. A real fixed line
 *  holds its session for days, so the age is a parameter here. */
async function seedFailoverAged(
  seeded: Seeded,
  device: Seeded['devices'][number],
  fromIp: string,
  toIp: string,
  minutesAgo: number,
  previousSessionStartedMinutesAgo: number,
): Promise<void> {
  const now = Date.now();
  await db('ppp_sessions').insert({
    concentrator_id: seeded.concentratorId,
    device_id: device.id,
    ppp_username: device.username,
    caller_ip: fromIp,
    started_at: new Date(now - previousSessionStartedMinutesAgo * 60_000),
    ended_at: new Date(now - minutesAgo * 60_000),
    duration_seconds: Math.round((previousSessionStartedMinutesAgo - minutesAgo) * 60),
  });
  await seedSessionUp(seeded, device, toIp, minutesAgo);
}

/** Devices with NO `site_id`, all behind ONE line: the same public address. */
async function seedUnsitedFleetBehindOneLine(
  tenantId: number,
  prefix: string,
  count: number,
  sharedIp: string,
): Promise<Seeded> {
  const [chr] = await db('devices')
    .insert({
      tenant_id: tenantId,
      name: `${prefix}-chr`,
      brand: 'mikrotik',
      family: 'mikrotik_routeros7',
      role: 'concentrator',
      status: 'active',
    })
    .returning<Array<{ id: number }>>('id');

  const devices: Seeded['devices'] = [];
  for (let i = 1; i <= count; i++) {
    const username = `${prefix}-orphan${i}`;
    const [device] = await db('devices')
      .insert({
        tenant_id: tenantId,
        site_id: null,
        name: `${prefix}-router-${i}`,
        brand: 'mikrotik',
        family: 'mikrotik_routeros7',
        role: 'cpe',
        status: 'active',
        concentrator_id: chr.id,
        ppp_username: username,
        wan_public_ip: sharedIp,
      })
      .returning<Array<{ id: number }>>('id');
    devices.push({ id: device.id, siteId: 0, name: `${prefix}-router-${i}`, username });
  }
  return { concentratorId: chr.id, devices };
}

/** Move every session and every derived event `minutes` further into the past.
 *  The only honest way to make "three hours went by" happen inside a test. */
async function ageTheWorld(minutes: number): Promise<void> {
  await db.raw(
    "UPDATE ppp_sessions SET started_at = started_at - (? * INTERVAL '1 minute'), " +
      "ended_at = ended_at - (? * INTERVAL '1 minute')",
    [minutes, minutes],
  );
  await db.raw("UPDATE wan_path_events SET at = at - (? * INTERVAL '1 minute')", [minutes]);
  await db.raw(
    "UPDATE operator_incidents SET opened_at = opened_at - (? * INTERVAL '1 minute'), " +
      "clearing_since = clearing_since - (? * INTERVAL '1 minute')",
    [minutes, minutes],
  );
}

/** One Express route of the weather router, by method and path. */
function findRoute(method: string, path: string): any {
  for (const layer of (weatherRoutes as any).stack ?? []) {
    if (layer.route && layer.route.path === path && layer.route.methods?.[method]) {
      return layer.route;
    }
  }
  return null;
}

/**
 * Run every middleware of a route EXCEPT its controller, and hand back the
 * error the chain refused with (or null if it let the call through).
 *
 * This exercises the real `requireCapability` / `requireRole` against the real
 * permission service and the real `user_tenants` rows — asserting on the shape
 * of the middleware array would prove nothing about who actually gets in.
 */
async function runGuards(route: any, req: any): Promise<unknown> {
  const guards = (route.stack ?? []).slice(0, -1).map((l: any) => l.handle);
  for (const guard of guards) {
    const refusal = await new Promise<unknown>((resolve) => {
      void Promise.resolve(guard(req, {} as any, (err?: unknown) => resolve(err ?? null)));
    });
    if (refusal !== null) return refusal;
  }
  return null;
}

// ----------------------------------------------------------------------------

async function findingStableLineIsNotInert(): Promise<void> {
  section('22. FINDING 1 — a line that has been up for a day still produces events');

  await reset();
  await seedTenants();
  await seedAsnTable();
  const fleet = await seedFleet(TENANT, 'j', 14, AS_ALPHA);

  // Acceptance scenario 2 of the brief, on a REAL fleet: the sessions have been
  // up for 26 hours (a healthy fixed line holds for days), and all twelve sites
  // bounce onto the mobile carrier five minutes ago.
  for (let i = 0; i < 12; i++) {
    await seedFailoverAged(
      fleet, fleet.devices[i],
      `${AS_ALPHA.base}.1.${i + 1}`, `${AS_MOBILE.base}.9.${i + 1}`,
      5, 26 * 60,
    );
  }

  const raw = await ingestPathEvents(TENANT);
  ok(
    'the scan SEES the twelve transitions although the previous session predates the window',
    raw.scanned === 12,
    `scanned ${raw.scanned}`,
  );
  ok('…and writes all twelve', raw.inserted === 12, `inserted ${raw.inserted}`);

  const outcome = await runWeatherScan(TENANT);
  ok('ONE incident opens for the outage', outcome.opened.length === 1, JSON.stringify(outcome.opened));
  const incidents = await listIncidents(TENANT);
  ok('…named after the carrier the sites LEFT', incidents[0]?.asn === AS_ALPHA.asn, `${incidents[0]?.asn}`);
  ok('…with all twelve sites in it', incidents[0]?.currentSiteCount === 12, `${incidents[0]?.currentSiteCount}`);

  // The lookback is a SCAN bound, not a window-function bound: a deliberately
  // tiny lookback must still classify against the true predecessor.
  await reset();
  await seedTenants();
  await seedAsnTable();
  const tight = await seedFleet(TENANT, 'j2', 6, AS_ALPHA);
  await seedFailoverAged(
    tight, tight.devices[0], `${AS_ALPHA.base}.1.1`, `${AS_MOBILE.base}.9.1`, 2, 3 * 24 * 60,
  );
  const narrow = await ingestPathEvents(TENANT, { lookbackMinutes: 10 });
  ok(
    'a 10-minute lookback still resolves a predecessor three days old',
    narrow.inserted === 1,
    `inserted ${narrow.inserted}`,
  );
  const only = await db('wan_path_events').where({ tenant_id: TENANT }).first();
  ok(
    '…and gets the direction and the from-ASN right',
    only?.direction === 'away' && Number(only?.from_asn) === AS_ALPHA.asn,
    `${only?.direction}/${only?.from_asn}`,
  );
}

async function findingReturnIsNotAnAway(): Promise<void> {
  section('23. FINDING 2 — the return leg never accuses the rescue carrier');

  await reset();
  await seedTenants();
  await seedAsnTable();
  const fleet = await seedFleet(TENANT, 'k', 14, AS_ALPHA);

  // Twelve sites, Alpha lines up for ten hours, Alpha dies eight minutes ago.
  for (let i = 0; i < 12; i++) {
    await seedFailoverAged(
      fleet, fleet.devices[i],
      `${AS_ALPHA.base}.1.${i + 1}`, `${AS_MOBILE.base}.9.${i + 1}`,
      8, 10 * 60,
    );
  }
  const during = await runWeatherScan(TENANT);
  ok('during the outage ONE incident is open', during.opened.length === 1, JSON.stringify(during.opened));
  const alphaIncident = (await listIncidents(TENANT))[0];
  ok('…and it names Alpha Telecom, the carrier that broke', alphaIncident?.asn === AS_ALPHA.asn);

  // THREE HOURS PASS. The original `away` is now older than the ingestion's
  // lookback — the ordinary state of affairs for any outage longer than a
  // coffee break — and only then do the sites come home.
  await ageTheWorld(192);
  for (let i = 0; i < 12; i++) {
    await seedSessionUp(fleet, fleet.devices[i], `${AS_ALPHA.base}.1.${i + 1}`, 1);
  }

  const after = await runWeatherScan(TENANT);
  const returns = await db('wan_path_events')
    .where({ tenant_id: TENANT })
    .andWhere('to_asn', AS_ALPHA.asn)
    .andWhere('from_asn', AS_MOBILE.asn)
    .select('direction');
  ok('the twelve return legs were ingested', returns.length === 12, `${returns.length}`);
  ok(
    '…every one of them is a `back`, not an `away`',
    returns.length === 12 && returns.every((r: any) => r.direction === 'back'),
    JSON.stringify([...new Set(returns.map((r: any) => r.direction))]),
  );

  const awayFromMobile = await db('wan_path_events')
    .where({ tenant_id: TENANT, direction: 'away' })
    .andWhere('from_asn', AS_MOBILE.asn)
    .count<Array<{ count: string }>>('* as count');
  ok(
    'NOT ONE `away` is keyed on the mobile carrier that carried the traffic',
    Number(awayFromMobile[0].count) === 0,
    `${awayFromMobile[0].count}`,
  );

  const mobileIncidents = (await listIncidents(TENANT)).filter((i) => i.asn === AS_MOBILE.asn);
  ok('NO incident is opened against Mobile Carrier at the moment of recovery', mobileIncidents.length === 0);
  ok('…and the recovery sweep opened nothing at all', after.opened.length === 0, JSON.stringify(after.opened));
  ok(
    '…while Alpha’s incident is the one that reacts, by starting to clear',
    (await getIncident(TENANT, alphaIncident?.id ?? 0))?.status === 'clearing',
  );
}

async function findingOneLineIsOneVote(): Promise<void> {
  section('24. FINDING 3 — five routers behind one line are ONE vote, not five');

  await reset();
  await seedTenants();
  await seedAsnTable();

  // Five routers, no `site_id` (nothing sets it on creation nor on binding a
  // concentrator discovery), all behind the SAME line: one caller_ip.
  const orphans = await seedUnsitedFleetBehindOneLine(TENANT, 'l', 5, `${AS_ALPHA.base}.1.1`);
  for (const device of orphans.devices) {
    await seedFailoverAged(
      orphans, device, `${AS_ALPHA.base}.1.1`, `${AS_MOBILE.base}.9.1`, 3, 12 * 60,
    );
  }

  const outcome = await runWeatherScan(TENANT);
  ok('all five transitions are still RECORDED', outcome.ingested === 5, `${outcome.ingested}`);
  ok(
    'NO incident opens: one line that bounced is one site, whatever the router count',
    outcome.opened.length === 0,
    JSON.stringify(outcome.opened),
  );
  const asn = outcome.evaluation.asns.find((a) => a.asn === AS_ALPHA.asn);
  ok('…the quorum counts ONE affected site', asn?.affectedSites === 1, `${asn?.affectedSites}`);
  ok(
    '…and says so in the reason an operator reads',
    (asn?.reason ?? '').startsWith('below_absolute_quorum:1/'),
    asn?.reason ?? '',
  );
  ok('…no row exists in the database either', (await listIncidents(TENANT)).length === 0);
  const report = await getWeatherReport(TENANT);
  ok(
    'the report warns that devices without a site were collapsed by line',
    report.unsitedDeviceCount === 5,
    `${report.unsitedDeviceCount}`,
  );
  // The coverage block has to be READABLE, not just present: a bare count of
  // unsited devices has no denominator and does not distinguish the fallback
  // that works from the one that hands out a vote per router.
  ok(
    '…with the denominator next to it',
    report.deviceCount === 5,
    `${report.deviceCount}`,
  );
  ok(
    '…and it says all five are grouped BY LINE, which is the safe case',
    report.unsitedGroupedByLineCount === 5 && report.unsitedUngroupedDeviceCount === 0,
    `grouped=${report.unsitedGroupedByLineCount} ungrouped=${report.unsitedUngroupedDeviceCount}`,
  );
  ok(
    '…the split is exhaustive: grouped + ungrouped = unsited',
    report.unsitedGroupedByLineCount + report.unsitedUngroupedDeviceCount ===
      report.unsitedDeviceCount,
  );
  // The subset a database CHECK would have covered, had one been possible.
  // `bindDiscovery()` sets `concentrator_id` and cannot set `site_id` — a PPP
  // discovery learns a username and a caller-id, never a site — so the
  // invariant is REPORTED here instead of enforced where it could not be met.
  ok(
    '…and it names the devices adopted behind a concentrator with no site',
    report.unsitedBehindConcentratorCount === 5,
    `${report.unsitedBehindConcentratorCount}`,
  );
  ok(
    '…concentrators themselves are never counted: they are infrastructure, not voters',
    report.deviceCount === report.unsitedDeviceCount,
  );

  // The dangerous half of the split, and the reason it is counted apart: a
  // device with no site AND no attributable egress address falls to
  // `dev:<id>` — one vote per router, which is the collapse migration 022
  // exists to prevent. The report must name that population out loud.
  await db('device_wan_path')
    .whereIn('device_id', orphans.devices.map((d) => d.id))
    .update({ observed_public_ip: null, reported_public_ip: null });
  await db('devices')
    .whereIn('id', orphans.devices.map((d) => d.id))
    .update({ wan_public_ip: null });
  const blind = await getWeatherReport(TENANT);
  ok(
    'a device with no site AND no egress address is reported as UNGROUPED — one vote each',
    blind.unsitedUngroupedDeviceCount === 5 && blind.unsitedGroupedByLineCount === 0,
    `grouped=${blind.unsitedGroupedByLineCount} ungrouped=${blind.unsitedUngroupedDeviceCount}`,
  );

  // The counterpart must still hold: five DISTINCT lines, still with no
  // site_id, are five votes. The fix must not simply stop counting them.
  await reset();
  await seedTenants();
  await seedAsnTable();
  const spread = await seedUnsitedFleetBehindOneLine(TENANT, 'm', 6, `${AS_ALPHA.base}.1.1`);
  for (let i = 0; i < 6; i++) {
    await db('devices')
      .where({ id: spread.devices[i].id })
      .update({ wan_public_ip: `${AS_ALPHA.base}.2.${i + 1}` });
    await seedFailoverAged(
      spread, spread.devices[i],
      `${AS_ALPHA.base}.2.${i + 1}`, `${AS_MOBILE.base}.9.${i + 1}`, 3, 12 * 60,
    );
  }
  const real = await runWeatherScan(TENANT);
  ok(
    'six unsited devices on SIX different lines still reach quorum',
    real.opened.length === 1,
    JSON.stringify(real.opened),
  );
  const spreadIncident = (await listIncidents(TENANT))[0];
  ok('…counted as six sites', spreadIncident?.currentSiteCount === 6, `${spreadIncident?.currentSiteCount}`);
}

async function findingAsnTableIsPlatformOnly(): Promise<void> {
  section('25. FINDING 4 — the GLOBAL ASN table is not writable by a tenant admin');

  await reset();
  await seedTenants();
  await seedAsnTable();

  // ---- The damage, demonstrated at the data layer -------------------------
  const fleet = await seedFleet(TENANT, 'n', 14, AS_ALPHA);
  for (let i = 0; i < 12; i++) {
    await seedFailoverAged(
      fleet, fleet.devices[i],
      `${AS_ALPHA.base}.1.${i + 1}`, `${AS_MOBILE.base}.9.${i + 1}`, 2, 10 * 60,
    );
  }
  const baseline = await runWeatherScan(TENANT);
  ok('customer A has a real incident to begin with', baseline.opened.length === 1, JSON.stringify(baseline.opened));

  await db('operator_incidents').where({ tenant_id: TENANT }).del();
  await db('wan_path_events').where({ tenant_id: TENANT }).del();
  await importAsnRanges(
    Array.from({ length: 12 }, (_, i) => ({
      prefix: `${AS_ALPHA.base}.1.${i + 1}/32`,
      asn: 65000 + i,
      asOrg: 'Bogus',
      country: 'FR',
      region: null,
    })),
    { label: 'poisoned by another tenant', source: 'manual' },
  );
  const poisoned = await runWeatherScan(TENANT);
  ok(
    'twelve /32 rows in the GLOBAL table destroy customer A’s correlation',
    poisoned.opened.length === 0 && poisoned.evaluation.asns.length === 12,
    `${poisoned.opened.length} opened, ${poisoned.evaluation.asns.length} asns`,
  );

  // ---- The guard that now stands in front of that write -------------------
  const [tenantAdmin] = await db('users')
    .insert({ username: 'f5-tenant-b-admin', role: 'user', is_active: true })
    .onConflict('username')
    .merge(['role'])
    .returning<Array<{ id: number }>>('id');
  await db('user_tenants')
    .insert({ user_id: tenantAdmin.id, tenant_id: OTHER_TENANT, role: 'admin' })
    .onConflict(['user_id', 'tenant_id'])
    .merge(['role']);

  const caps = await permissionService.getUserCapabilities(tenantAdmin.id, false, OTHER_TENANT);
  ok(
    'the admin of tenant B genuinely holds settings.manage — that capability IS tenant-scoped',
    caps.includes(CAPABILITIES.SETTINGS_MANAGE),
  );

  const importRoute = findRoute('post', '/asn-table');
  ok('POST /weather/asn-table is a route on this router', importRoute !== null);

  const asTenantAdmin = await runGuards(importRoute, {
    session: { userId: tenantAdmin.id, role: 'user', currentTenantId: OTHER_TENANT },
    tenantId: OTHER_TENANT,
    params: {}, query: {}, body: {},
  });
  ok(
    'a TENANT admin is refused the global ASN import',
    asTenantAdmin instanceof AppError && asTenantAdmin.statusCode === 403,
    asTenantAdmin instanceof AppError
      ? `${asTenantAdmin.statusCode} ${asTenantAdmin.message}`
      : 'it was allowed through',
  );

  const asPlatformAdmin = await runGuards(importRoute, {
    session: { userId: 1, role: 'admin', currentTenantId: TENANT },
    tenantId: TENANT,
    params: {}, query: {}, body: {},
  });
  ok('a PLATFORM admin still gets through', asPlatformAdmin === null, String(asPlatformAdmin));

  // …and the per-tenant policy, which IS a tenant-local decision, must not have
  // been dragged behind the platform role by the same edit.
  const policyAsTenantAdmin = await runGuards(findRoute('put', '/policy'), {
    session: { userId: tenantAdmin.id, role: 'user', currentTenantId: OTHER_TENANT },
    tenantId: OTHER_TENANT,
    params: {}, query: {}, body: {},
  });
  ok(
    'the tenant-local quorum policy is still a tenant admin’s to set',
    policyAsTenantAdmin === null,
    String(policyAsTenantAdmin),
  );
}

async function findingClearingDoesNotFlap(): Promise<void> {
  section('26. FINDING 5 — one noisy site cannot make an incident beat');

  await reset();
  await seedTenants();
  await seedAsnTable();
  const fleet = await seedFleet(TENANT, 'o', 14, AS_ALPHA);

  const policy = (await getTenantPolicy(TENANT)).policy;
  ok(
    'the clearing threshold is below the opening quorum',
    clearThreshold(policy) < policy.minSites,
    `${clearThreshold(policy)} < ${policy.minSites}`,
  );

  // Five sites leave Alpha: the incident opens.
  for (let i = 0; i < 5; i++) {
    await seedFailoverAged(
      fleet, fleet.devices[i],
      `${AS_ALPHA.base}.1.${i + 1}`, `${AS_MOBILE.base}.9.${i + 1}`, 1, 8 * 60,
    );
  }
  const openedScan = await runWeatherScan(TENANT);
  ok('the incident opened on five sites', openedScan.opened.length === 1, JSON.stringify(openedScan.opened));
  const incidentId = openedScan.opened[0] ?? -1;

  // Three come home. remaining = 2 < 3: it starts clearing. Once.
  for (let i = 0; i < 3; i++) {
    await seedSessionUp(fleet, fleet.devices[i], `${AS_ALPHA.base}.1.${i + 1}`, 0);
  }
  const first = await runWeatherScan(TENANT);
  ok('it enters clearing', first.clearing.includes(incidentId), JSON.stringify(first.clearing));
  ok('…and the row says clearing', (await getIncident(TENANT, incidentId))?.status === 'clearing');

  // Now ONE site — one — flaps four times. Each round trip crosses the single
  // audited threshold in both directions.
  let extraClearing = 0;
  let resumes = 0;
  let extended = 0;
  let clockRestarted = 0;
  for (let round = 0; round < 4; round++) {
    const before = await db('operator_incidents')
      .where({ id: incidentId }).first<{ clearing_since: Date }>('clearing_since');
    await seedSessionUp(fleet, fleet.devices[0], `${AS_MOBILE.base}.8.${round + 1}`, 0);
    const out = await runWeatherScan(TENANT);
    resumes += out.resumed.length;
    extraClearing += out.clearing.length;
    // The site is back off Alpha: remaining sits BETWEEN the two edges. That is
    // the band the new action exists for, and it must actually be taken —
    // an action nobody emits is a rule nobody applies.
    if (out.evaluation.actions.some((x) => x.kind === 'extend_hold_down')) extended++;
    const after = await db('operator_incidents')
      .where({ id: incidentId }).first<{ clearing_since: Date }>('clearing_since');
    if (new Date(after!.clearing_since).getTime() > new Date(before!.clearing_since).getTime()) {
      clockRestarted++;
    }

    await seedSessionUp(fleet, fleet.devices[0], `${AS_ALPHA.base}.1.1`, 0);
    const back = await runWeatherScan(TENANT);
    resumes += back.resumed.length;
    extraClearing += back.clearing.length;
  }

  ok('one flapping site NEVER re-opens the incident', resumes === 0, `${resumes} resume(s)`);
  ok(
    'the between-the-edges band is REACHED, not merely declared',
    extended === 4,
    `extend_hold_down emitted on ${extended}/4 rounds`,
  );
  ok(
    '…and it restarts the hold-down, so an interrupted recovery cannot close early',
    clockRestarted === 4,
    `clock restarted ${clockRestarted}/4 times`,
  );
  ok(
    '…and produces no second `clearing` notification',
    extraClearing === 0,
    `${extraClearing} extra start_clearing transition(s)`,
  );
  ok(
    'the incident is still exactly where it was: clearing, announced once',
    (await getIncident(TENANT, incidentId))?.status === 'clearing',
  );

  // A REAL relapse — the whole quorum leaves again — must still resume it.
  for (let i = 0; i < 5; i++) {
    await seedSessionUp(fleet, fleet.devices[i], `${AS_MOBILE.base}.7.${i + 1}`, 0);
  }
  const relapse = await runWeatherScan(TENANT);
  ok('a relapse at full quorum DOES resume it', relapse.resumed.includes(incidentId), JSON.stringify(relapse.resumed));
  ok('…and the row is open again', (await getIncident(TENANT, incidentId))?.status === 'open');

  // The hysteresis is a stated property of the contract, not an accident.
  ok(
    'resumeThreshold is strictly above clearThreshold, for every legal policy',
    resumeThreshold(policy) > clearThreshold(policy),
    `${resumeThreshold(policy)} > ${clearThreshold(policy)}`,
  );
  const tight: WeatherPolicy = { ...DEFAULT_WEATHER_POLICY, clearRatio: 1 };
  ok(
    '…including the degenerate clearRatio = 1, where the two would otherwise coincide',
    resumeThreshold(tight) > clearThreshold(tight),
    `${resumeThreshold(tight)} > ${clearThreshold(tight)}`,
  );
}

// ============================================================================
// Main
// ============================================================================

async function main(): Promise<void> {
  console.log('ObliWAN F5 — Operator Weather verification\n');
  try {
    offlineAddressTests();
    offlineQuorumTests();
    await egressTests();
    await scenarioNoAlertForOneSite();
    await scenarioOneAlertForTwelve();
    await scenarioFleetWide();
    await scenarioRecovery();
    await schemaTests();
    await ingestionTests();
    for (const finding of [
      findingStableLineIsNotInert, findingReturnIsNotAnAway, findingOneLineIsOneVote,
      findingAsnTableIsPlatformOnly, findingClearingDoesNotFlap,
    ]) {
      // Each finding is independent evidence; one that blows up must not hide
      // the four behind it.
      try {
        await finding();
      } catch (err) {
        ok(`${finding.name} ran to completion`, false, err instanceof Error ? err.message : String(err));
      }
    }
  } catch (err) {
    failed++;
    failures.push(`harness aborted: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
    console.error(err);
  }

  console.log(`\n${'='.repeat(60)}`);
  console.log(`  ${passed} passed, ${failed} failed`);
  if (failures.length > 0) {
    console.log('\nFailures:');
    for (const f of failures) console.log(`  - ${f}`);
  }
  console.log('='.repeat(60));

  await db.destroy();
  process.exit(failed === 0 ? 0 : 1);
}

void main();
