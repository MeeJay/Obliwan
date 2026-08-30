// ============================================================================
// ObliWAN — M11 intent fixtures
// ============================================================================
//
// Three intents, and each of them exists to prove one sentence:
//
//   `referenceSiteIntent()`  ONE site description compiles for all four brands.
//   `zoneAndCommitIntent()`  the same site, with two demands only a SonicWall
//                            can meet — MikroTik, DrayTek and Zyxel are refused
//                            BY NAME, at compilation, with no network access.
//   `deadManIntent()`        a demand the FAMILY can meet but OUR DRIVER does
//                            not declare — the refusal names the
//                            `DeviceCapabilities` flag rather than blaming the
//                            hardware.
//
// No equipment of any brand exists. These are documents, and everything they
// are used to check is a pure function of them.

import type { SiteIntentDocument } from '@obliwan/shared/dist/intent';
import { SiteIntentDocument as SiteIntentSchema } from '@obliwan/shared/dist/intent';

/** A two-uplink, two-segment branch office: the shape of nearly every site an
 *  MSP actually deploys. */
export function referenceSiteIntent(): SiteIntentDocument {
  return SiteIntentSchema.parse({
    schemaVersion: 1,
    slug: 'lyon-nord',
    name: 'Lyon Nord',
    description: 'Reference branch office: FTTH on VLAN 832, static backup, office + guest.',
    wan: [
      {
        id: 'wan1',
        role: 'primary',
        mode: 'pppoe',
        uplinkIndex: 1,
        address: null,
        gateway: null,
        vlanId: 832,
        pppoeUsername: 'lyon-nord@isp.example',
        pppoeSecretRef: 'ref:lyon-nord-pppoe',
        mtu: 1492,
      },
      {
        id: 'wan2',
        role: 'backup',
        mode: 'static',
        uplinkIndex: 2,
        address: '192.0.2.10/29',
        gateway: '192.0.2.9',
        vlanId: null,
        pppoeUsername: null,
        pppoeSecretRef: null,
        mtu: null,
      },
    ],
    lans: [
      {
        id: 'office',
        name: 'Office',
        vlanId: null,
        gatewayCidr: '10.20.0.1/24',
        dhcp: {
          poolFrom: '10.20.0.100',
          poolTo: '10.20.0.200',
          dnsServers: ['10.20.0.1'],
          domain: 'lyon-nord.example',
          leaseSeconds: 28800,
          reservations: [{ mac: 'aa:bb:cc:dd:ee:01', address: '10.20.0.10', hostname: 'nas' }],
        },
        isolated: false,
        internetAccess: true,
        accessPorts: [1, 2],
      },
      {
        id: 'guest',
        name: 'Guest',
        vlanId: 30,
        gatewayCidr: '10.20.30.1/24',
        dhcp: {
          poolFrom: '10.20.30.100',
          poolTo: '10.20.30.200',
          dnsServers: ['9.9.9.9'],
          domain: null,
          leaseSeconds: 3600,
          reservations: [],
        },
        isolated: true,
        internetAccess: true,
        accessPorts: [3],
      },
    ],
    policy: {
      defaultInbound: 'drop',
      interSegment: 'deny',
      allowPingFromWan: false,
      publish: [
        {
          id: 'nas-web',
          wan: 'wan1',
          protocol: 'tcp',
          externalPort: 443,
          toSegment: 'office',
          toAddress: '10.20.0.10',
          toPort: 8443,
          fromSources: ['203.0.113.0/24'],
          comment: 'NAS web console',
        },
      ],
      zones: [],
    },
    vpn: [
      {
        id: 'hq',
        remote: 'vpn.example.net',
        exchangeMode: 'ike2',
        pskRef: 'ref:lyon-nord-hq-psk',
        localSubnets: ['10.20.0.0/24'],
        remoteSubnets: ['10.10.0.0/16'],
        encryption: ['aes-256-cbc'],
        integrity: ['sha256'],
        dhGroup: ['modp2048'],
        dpdSeconds: 30,
      },
    ],
    management: {
      services: [
        { service: 'ssh', enabled: true, allowedFrom: ['10.255.0.0/24'], port: null },
        { service: 'https', enabled: true, allowedFrom: ['10.255.0.0/24'], port: null },
      ],
      snmp: {
        version: 'v2c',
        credentialRef: 'ref:lyon-nord-snmp',
        username: null,
        allowedFrom: ['10.255.0.0/24'],
      },
      localUsers: [
        {
          username: 'obliwan-svc',
          group: 'full',
          passwordRef: 'ref:lyon-nord-admin',
          allowedFrom: ['10.255.0.0/24'],
        },
      ],
    },
    qos: {
      wan: 'wan1',
      downBps: 1_000_000_000,
      upBps: 400_000_000,
      segments: [{ segment: 'guest', maxDownBps: 100_000_000, maxUpBps: 20_000_000, priority: 6 }],
    },
    safety: {
      requireOnDeviceDeadMan: false,
      requireAtomicCommit: false,
      forbidRebootToApply: false,
      requireStructuredDiff: false,
    },
    // Nothing is claimed exhaustively: the compiled document may only ever
    // produce `changed` findings on records ObliWAN itself wrote.
    authoritative: [],
  });
}

/**
 * The same site, with three demands added:
 *   - a named zone policy       (MikroTik and DrayTek have no zone model)
 *   - SNMP v3                   (not claimed for the Vigor range)
 *   - an atomic commit, and no reboot to apply
 * Only the SonicWall can satisfy all of them.
 */
export function zoneAndCommitIntent(): SiteIntentDocument {
  const base = referenceSiteIntent();
  return SiteIntentSchema.parse({
    ...base,
    slug: 'lyon-sud',
    name: 'Lyon Sud',
    policy: {
      ...base.policy,
      zones: [
        {
          id: 'guest-no-office',
          from: 'guest',
          to: 'office',
          action: 'deny',
          protocol: null,
          ports: [],
          comment: 'guests never reach the office segment',
        },
      ],
    },
    management: {
      ...base.management,
      snmp: {
        version: 'v3',
        credentialRef: 'ref:lyon-sud-snmp',
        username: 'obliwan',
        allowedFrom: ['10.255.0.0/24'],
      },
    },
    safety: {
      requireOnDeviceDeadMan: false,
      requireAtomicCommit: true,
      forbidRebootToApply: true,
      requireStructuredDiff: true,
    },
  });
}

/**
 * A demand RouterOS genuinely supports (`/system/scheduler start-time=startup`
 * is the K1 dead-man) but that the MikroTik driver has not declared. The
 * refusal must therefore name `canScheduleOnDevice` and not pretend the router
 * cannot do it.
 */
export function deadManIntent(): SiteIntentDocument {
  const base = referenceSiteIntent();
  return SiteIntentSchema.parse({
    ...base,
    slug: 'lyon-est',
    name: 'Lyon Est',
    safety: { ...base.safety, requireOnDeviceDeadMan: true },
  });
}

/** A compile target with everything pinned, so a golden file is a golden file
 *  and not "a golden file except the timestamp". */
export const GOLDEN_TARGET = {
  deviceId: 4242,
  tenantId: 7,
  model: 'GOLDEN',
  serial: 'GOLDEN-0001',
  systemIdentity: 'lyon-nord-cpe',
  pppUsername: 'lyon-nord@isp.example',
  osVersion: null,
  capturedAt: '2026-01-01T00:00:00.000Z',
} as const;
