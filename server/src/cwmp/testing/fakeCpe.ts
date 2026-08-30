/**
 * ObliWAN — `fakeCpe.ts`. A TR-069 client that lies the way real ones do.
 *
 * ┌─ WRITTEN BEFORE THE ACS, ON PURPOSE (risk R13) ───────────────────────────┐
 * │ `genieacs-sim` is abandoned and there is no DrayTek or Zyxel on this       │
 * │ machine (§8.3). If the simulator is written after the server it inherits   │
 * │ the server's misunderstandings and every test passes for the wrong         │
 * │ reason. So this file came first and it is deliberately INDEPENDENT:        │
 * │                                                                           │
 * │  - it builds envelopes as raw strings, the way firmware does, and shares   │
 * │    NOTHING with `../xml.ts`. A serialiser bug therefore cannot cancel out  │
 * │    against a parser bug — the two implementations were written from the    │
 * │    specification, not from each other;                                    │
 * │  - it validates every ACS response with `XMLValidator` before looking at   │
 * │    it, so "the ACS emitted well-formed XML" is an assertion and not an     │
 * │    assumption;                                                            │
 * │  - it speaks HTTP through `node:http` directly, because the interesting    │
 * │    behaviour is in the headers: Digest, cookies, `Content-Length: 0`.      │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE QUIRKS, AND WHY THESE FIVE ──────────────────────────────────────────┐
 * │ Every one of them is a real, documented failure mode of shipped CPE       │
 * │ firmware, and each one breaks a DIFFERENT layer of the ACS:               │
 * │                                                                           │
 * │  noCookie          the CPE ignores `Set-Cookie`. Breaks session           │
 * │                    continuity -> forces the `(cwmp_id, source IP)`        │
 * │                    fallback.                                              │
 * │  singleElementArray  ONE `ParameterValueStruct` instead of a list.        │
 * │                    Without `isArray` in the parser this becomes an        │
 * │                    object and `.map()` throws — the single most common    │
 * │                    way a hand-rolled ACS dies in production.              │
 * │  badXsiType        `xsi:type="string"`, `boolean`, or none at all.        │
 * │                    Breaks any code that trusts the literal.               │
 * │  noCwmpId          no `cwmp:ID` SOAP header. Legal (the header is         │
 * │                    optional) and it breaks request/response matching.     │
 * │  basicAuthOnly     the CPE refuses Digest. The ACS must notice rather     │
 * │                    than loop on 401 forever.                              │
 * │                                                                           │
 * │ `emptyPost` is NOT in that list because an empty POST is not a quirk: it  │
 * │ is the protocol. The ACS only ever speaks on an empty POST, and this      │
 * │ client sends one after every response exactly as TR-069 §3.7.1.4 says.    │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * WHAT THIS PROVES AND WHAT IT DOES NOT: it proves the ACS's protocol layer —
 * session machine, digest, cookies, parser, serialiser, task dispatch, transfer
 * correlation, secret suppression. It proves NOTHING about a Vigor or a VMG.
 * There is no such hardware here and this file is not evidence that there is.
 */

import http from 'http';
import crypto from 'crypto';
import { XMLValidator } from 'fast-xml-parser';

// ============================================================================
// Configuration
// ============================================================================

export interface FakeCpeQuirks {
  /** Ignore `Set-Cookie`; never echo `ACSsession` back. */
  noCookie?: boolean;
  /** Send a single `ParameterValueStruct` where a list is expected. */
  singleElementArray?: boolean;
  /** Emit `xsi:type="string"` / no type at all instead of `xsd:string`. */
  badXsiType?: boolean;
  /** Omit the `cwmp:ID` SOAP header. */
  noCwmpId?: boolean;
  /** Refuse Digest, offer only Basic. */
  basicAuthOnly?: boolean;
  /** Announce a `soap-enc:arrayType` count that disagrees with the children. */
  arrayCountMismatch?: boolean;
  /**
   * Refuse a `SetParameterValues` with 9007 and REPEAT THE REJECTED VALUE in
   * the fault — twice, the way firmware really does it: once in the CWMP
   * fault string and once inside the `SetParameterValuesFault` struct beside
   * the parameter name.
   *
   * Documented on DrayTek and on Zyxel, and the reason `cwmp_tasks.fault` is
   * a place a vault plaintext comes back out: `serialiseTask` decrypted the
   * value one HTTP request ago and the CPE is now handing it back.
   */
  echoRejectedValueInFault?: boolean;
}

export interface FakeCpeOptions {
  host: string;
  port: number;
  /** Path the CPE was provisioned with, e.g. `/acme`. */
  path: string;
  oui: string;
  productClass?: string | null;
  serialNumber: string;
  manufacturer?: string;
  dataModel: 'tr098' | 'tr181';
  username?: string;
  password?: string;
  quirks?: FakeCpeQuirks;
  /** Print every envelope. Off by default: a 40-CPE run is unreadable with it on. */
  verbose?: boolean;
}

/** One HTTP exchange, kept so a test can assert on the wire and not just on the DB. */
export interface Exchange {
  requestBody: string;
  status: number;
  responseBody: string;
  headers: http.IncomingHttpHeaders;
  /** `XMLValidator` verdict on the ACS's response. `null` for an empty body. */
  xmlValid: boolean | null;
  xmlError?: string;
}

export interface SessionResult {
  exchanges: Exchange[];
  /** RPC method names the ACS sent, in order. */
  rpcsReceived: string[];
  /** Faults the CPE returned to the ACS. */
  faultsSent: string[];
  authChallenges: number;
  cookieOffered: boolean;
  durationMs: number;
  error?: string;
}

// ============================================================================
// The parameter trees — two models, one box
// ============================================================================

interface Leaf {
  value: string;
  type: string;
  writable: boolean;
}

/**
 * A TR-098 tree with the shape a Vigor actually exposes, INCLUDING the
 * credentials. The PPPoE password and the Wi-Fi passphrase are in here
 * precisely so a test can go and check that the ACS did not store them.
 */
function tr098Tree(o: FakeCpeOptions): Record<string, Leaf> {
  const R = 'InternetGatewayDevice.';
  return {
    [`${R}DeviceInfo.Manufacturer`]: str(o.manufacturer ?? 'DrayTek'),
    [`${R}DeviceInfo.ManufacturerOUI`]: str(o.oui),
    [`${R}DeviceInfo.ProductClass`]: str(o.productClass ?? 'Vigor2927'),
    [`${R}DeviceInfo.SerialNumber`]: str(o.serialNumber),
    [`${R}DeviceInfo.HardwareVersion`]: str('R2'),
    [`${R}DeviceInfo.SoftwareVersion`]: str('4.4.5.1'),
    [`${R}DeviceInfo.UpTime`]: num('184523', 'xsd:unsignedInt'),

    [`${R}ManagementServer.URL`]: str(`http://${o.host}:${o.port}${o.path}`, true),
    [`${R}ManagementServer.Username`]: str(o.username ?? '', true),
    [`${R}ManagementServer.Password`]: str(o.password ?? '', true),
    [`${R}ManagementServer.PeriodicInformEnable`]: bool('1', true),
    [`${R}ManagementServer.PeriodicInformInterval`]: num('300', 'xsd:unsignedInt', true),
    [`${R}ManagementServer.ConnectionRequestURL`]: str(
      'http://192.168.1.1:7547/cr',
    ),
    [`${R}ManagementServer.ParameterKey`]: str('', true),

    [`${R}WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Enable`]: bool('1', true),
    [`${R}WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ConnectionStatus`]:
      str('Connected'),
    [`${R}WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress`]:
      str('81.250.14.7'),
    [`${R}WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ConnectionType`]:
      str('IP_Routed', true),
    [`${R}WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.MACAddress`]:
      str('00:50:7F:11:22:33'),
    [`${R}WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Uptime`]:
      num('184100', 'xsd:unsignedInt'),
    // ── THE SECRETS ────────────────────────────────────────────────────────
    [`${R}WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username`]:
      str('adsl-client-4471@isp.fr', true),
    [`${R}WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Password`]:
      str('Hunter2-L2TP-PPPoE!', true),

    [`${R}LANDevice.1.LANHostConfigManagement.IPInterface.1.IPInterfaceIPAddress`]:
      str('192.168.1.1', true),
    [`${R}LANDevice.1.LANHostConfigManagement.IPInterface.1.IPInterfaceSubnetMask`]:
      str('255.255.255.0', true),
    [`${R}LANDevice.1.LANHostConfigManagement.DHCPServerEnable`]: bool('1', true),
    [`${R}LANDevice.1.LANHostConfigManagement.MinAddress`]: str('192.168.1.10', true),
    [`${R}LANDevice.1.LANHostConfigManagement.MaxAddress`]: str('192.168.1.200', true),
    [`${R}LANDevice.1.Hosts.HostNumberOfEntries`]: num('12', 'xsd:unsignedInt'),

    [`${R}LANDevice.1.WLANConfiguration.1.Enable`]: bool('1', true),
    [`${R}LANDevice.1.WLANConfiguration.1.SSID`]: str('Cabinet-Dupont', true),
    [`${R}LANDevice.1.WLANConfiguration.1.Channel`]: num('6', 'xsd:unsignedInt', true),
    [`${R}LANDevice.1.WLANConfiguration.1.BeaconType`]: str('11i', true),
    // ── MORE SECRETS ───────────────────────────────────────────────────────
    [`${R}LANDevice.1.WLANConfiguration.1.KeyPassphrase`]: str('WifiSecret2026#', true),
    [`${R}LANDevice.1.WLANConfiguration.1.PreSharedKey.1.PreSharedKey`]:
      str('0123456789abcdef0123456789abcdef', true),
  };
}

/** The same box, described by TR-181. Different paths, identical facts. */
function tr181Tree(o: FakeCpeOptions): Record<string, Leaf> {
  const R = 'Device.';
  return {
    [`${R}DeviceInfo.Manufacturer`]: str(o.manufacturer ?? 'Zyxel'),
    [`${R}DeviceInfo.ManufacturerOUI`]: str(o.oui),
    [`${R}DeviceInfo.ProductClass`]: str(o.productClass ?? 'DX5401-B0'),
    [`${R}DeviceInfo.SerialNumber`]: str(o.serialNumber),
    [`${R}DeviceInfo.HardwareVersion`]: str('V1.0'),
    [`${R}DeviceInfo.SoftwareVersion`]: str('V5.70(ACGB.3)C0'),
    [`${R}DeviceInfo.UpTime`]: num('54021', 'xsd:unsignedInt'),

    [`${R}ManagementServer.URL`]: str(`http://${o.host}:${o.port}${o.path}`, true),
    [`${R}ManagementServer.Username`]: str(o.username ?? '', true),
    [`${R}ManagementServer.Password`]: str(o.password ?? '', true),
    [`${R}ManagementServer.PeriodicInformEnable`]: bool('1', true),
    [`${R}ManagementServer.PeriodicInformInterval`]: num('300', 'xsd:unsignedInt', true),
    [`${R}ManagementServer.ConnectionRequestURL`]: str('http://10.64.0.9:7547/cr'),
    [`${R}ManagementServer.ParameterKey`]: str('', true),

    [`${R}PPP.Interface.1.Status`]: str('Up'),
    [`${R}PPP.Interface.1.ConnectionStatus`]: str('Connected'),
    [`${R}PPP.Interface.1.Username`]: str('fttx-9912@carrier.net', true),
    [`${R}PPP.Interface.1.Password`]: str('CarrierPPP-2026!', true),
    [`${R}IP.Interface.2.IPv4Address.1.IPAddress`]: str('90.11.202.44'),
    [`${R}Ethernet.Link.1.MACAddress`]: str('5C:6A:80:AA:BB:CC'),

    [`${R}IP.Interface.1.IPv4Address.1.IPAddress`]: str('192.168.1.1', true),
    [`${R}IP.Interface.1.IPv4Address.1.SubnetMask`]: str('255.255.255.0', true),
    [`${R}DHCPv4.Server.Pool.1.Enable`]: bool('1', true),
    [`${R}DHCPv4.Server.Pool.1.MinAddress`]: str('192.168.1.33', true),
    [`${R}DHCPv4.Server.Pool.1.MaxAddress`]: str('192.168.1.254', true),
    [`${R}Hosts.HostNumberOfEntries`]: num('7', 'xsd:unsignedInt'),

    [`${R}WiFi.SSID.1.Enable`]: bool('1', true),
    [`${R}WiFi.SSID.1.SSID`]: str('Maison-Martin', true),
    [`${R}WiFi.Radio.1.Channel`]: num('11', 'xsd:unsignedInt', true),
    [`${R}WiFi.AccessPoint.1.Security.ModeEnabled`]: str('WPA2-Personal', true),
    [`${R}WiFi.AccessPoint.1.Security.KeyPassphrase`]: str('MartinWifi!2026', true),
    [`${R}WiFi.AccessPoint.1.Security.PreSharedKey`]: str('deadbeefcafebabe', true),
  };
}

const str = (value: string, writable = false): Leaf => ({ value, type: 'xsd:string', writable });
const num = (value: string, type: string, writable = false): Leaf => ({ value, type, writable });
const bool = (value: string, writable = false): Leaf => ({ value, type: 'xsd:boolean', writable });

// ============================================================================
// The client
// ============================================================================

export class FakeCpe {
  readonly opts: FakeCpeOptions;
  readonly tree: Record<string, Leaf>;
  readonly root: string;

  /** Reboots the ACS asked for, so a test can assert the RPC arrived. */
  rebootCount = 0;
  /** Downloads the ACS asked for: `{ url, commandKey, fileType }`. */
  downloads: Array<{ url: string; commandKey: string; fileType: string }> = [];
  /** Writes the ACS performed, applied to the tree. */
  setsApplied: Array<{ path: string; value: string }> = [];

  private cookie: string | null = null;
  private nc = 0;
  private cnonce = crypto.randomBytes(8).toString('hex');
  private lastChallenge: Record<string, string> | null = null;

  constructor(opts: FakeCpeOptions) {
    this.opts = opts;
    this.root = opts.dataModel === 'tr098' ? 'InternetGatewayDevice.' : 'Device.';
    this.tree = opts.dataModel === 'tr098' ? tr098Tree(opts) : tr181Tree(opts);
  }

  get cwmpId(): string {
    const pc = (this.opts.productClass ?? '').trim();
    return pc
      ? `${this.opts.oui}-${pc}-${this.opts.serialNumber}`
      : `${this.opts.oui}-${this.opts.serialNumber}`;
  }

  /** Values the ACS must never have stored. Used by the assertions. */
  secretValues(): string[] {
    return Object.entries(this.tree)
      .filter(([path]) => /password|passphrase|presharedkey/i.test(path.split('.').pop() ?? ''))
      .map(([, leaf]) => leaf.value)
      .filter((v) => v.length > 0);
  }

  // ── Three doors for the replay test, and nothing else uses them ──────────
  //
  // An on-path observer does not run a session: it copies ONE
  // `Authorization: Digest …` header off the wire and re-sends it. Reproducing
  // that needs the three pieces `session()` keeps to itself — the envelope, the
  // header computed from a challenge, and a POST that sends exactly what it is
  // given. They are exposed rather than reimplemented in the test so that the
  // replayed bytes are the SAME bytes the honest CPE sent; a test that built
  // its own header would prove something about the test's md5, not about the
  // ACS.

  /** The exact Inform this CPE would send. */
  buildInform(events: string[] = ['2 PERIODIC']): string {
    return this.informEnvelope(events);
  }

  /** The exact `Authorization` header this CPE would answer a challenge with. */
  authFor(challenge: Record<string, string>): string {
    return this.authorization(challenge);
  }

  /** One POST, verbatim: no retry, no challenge handling, no interpretation. */
  postRaw(body: string, authorization: string | null): Promise<Exchange> {
    return this.rawPost(body, authorization);
  }

  /**
   * Run one complete CWMP session, from the Inform to the ACS's silence.
   *
   * The loop is the protocol: after every response the CPE sends an EMPTY POST,
   * and it is that empty POST — not a request — that gives the ACS its turn to
   * speak. The session ends when the ACS answers 204 or an empty 200.
   */
  async session(events: string[] = ['2 PERIODIC'], maxRpcs = 24): Promise<SessionResult> {
    const started = Date.now();
    const result: SessionResult = {
      exchanges: [],
      rpcsReceived: [],
      faultsSent: [],
      authChallenges: 0,
      cookieOffered: false,
      durationMs: 0,
    };

    try {
      // ── 1. Inform ────────────────────────────────────────────────────────
      let exchange = await this.post(this.informEnvelope(events), result);
      if (exchange.status !== 200) {
        result.error = `Inform rejected with HTTP ${exchange.status}`;
        result.durationMs = Date.now() - started;
        return result;
      }
      if (!/InformResponse/.test(exchange.responseBody)) {
        result.error = 'ACS did not answer InformResponse';
        result.durationMs = Date.now() - started;
        return result;
      }

      // ── 2. The empty-POST loop ───────────────────────────────────────────
      //
      // The loop body is uniform, and that is what makes it correct against
      // both ACS styles. A pipelining ACS answers our RPC response with the
      // NEXT request; a strict one answers 204 and waits for another empty
      // POST. Sending `next` — which is either an answer or the empty string —
      // covers both without a special case, and a client that special-cased
      // one of them would silently drop the tasks of the other.
      let next = '';
      for (let i = 0; i < maxRpcs; i++) {
        exchange = await this.post(next, result);
        if (exchange.status >= 400) {
          result.error = `ACS answered HTTP ${exchange.status}`;
          break;
        }
        // 204, or 200 with nothing in it: the ACS has no more to say.
        if (exchange.status === 204 || exchange.responseBody.trim() === '') break;

        const method = firstRpcMethod(exchange.responseBody);
        if (!method) {
          result.error = `unrecognised ACS envelope: ${exchange.responseBody.slice(0, 200)}`;
          break;
        }
        result.rpcsReceived.push(method);
        next = this.answer(method, exchange.responseBody, result);
      }
    } catch (err) {
      result.error = err instanceof Error ? err.message : String(err);
    }

    result.durationMs = Date.now() - started;
    return result;
  }

  /**
   * Report a completed transfer.
   *
   * Sent in a SEPARATE session, which is the whole point of the CommandKey
   * correlation: on real hardware the firmware image is fetched and applied
   * across a reboot, and the ACS that hears about it is not the process that
   * asked for it.
   */
  async transferComplete(
    commandKey: string,
    faultCode = '0',
    faultString = '',
  ): Promise<SessionResult> {
    const started = Date.now();
    const result: SessionResult = {
      exchanges: [],
      rpcsReceived: [],
      faultsSent: [],
      authChallenges: 0,
      cookieOffered: false,
      durationMs: 0,
    };
    try {
      await this.post(this.informEnvelope(['7 TRANSFER COMPLETE']), result);
      const body = this.transferCompleteEnvelope(commandKey, faultCode, faultString);
      const ex = await this.post(body, result);
      if (!/TransferCompleteResponse/.test(ex.responseBody) && ex.status === 200) {
        result.error = 'ACS did not answer TransferCompleteResponse';
      }
      await this.post('', result); // close the session politely
    } catch (err) {
      result.error = err instanceof Error ? err.message : String(err);
    }
    result.durationMs = Date.now() - started;
    return result;
  }

  // ── Envelope construction — raw strings, like firmware ────────────────────

  private header(id: string): string {
    if (this.opts.quirks?.noCwmpId) return '<soap:Header/>';
    return `<soap:Header><cwmp:ID soap:mustUnderstand="1">${id}</cwmp:ID></soap:Header>`;
  }

  private envelope(id: string, body: string): string {
    return (
      '<?xml version="1.0" encoding="UTF-8"?>' +
      '<soap:Envelope ' +
      'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" ' +
      'xmlns:soap-enc="http://schemas.xmlsoap.org/soap/encoding/" ' +
      'xmlns:xsd="http://www.w3.org/2001/XMLSchema" ' +
      'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' +
      'xmlns:cwmp="urn:dslforum-org:cwmp-1-0">' +
      this.header(id) +
      `<soap:Body>${body}</soap:Body>` +
      '</soap:Envelope>'
    );
  }

  /** `xsi:type` exactly as this CPE writes it — correctly, or badly. */
  private xsi(type: string): string {
    if (!this.opts.quirks?.badXsiType) return ` xsi:type="${type}"`;
    // Three real spellings, cycled so one session exercises all of them.
    const bad = ['string', 'xs:string', ''];
    const pick = bad[this.setsApplied.length % bad.length];
    return pick ? ` xsi:type="${pick}"` : '';
  }

  private valueStructs(entries: Array<[string, Leaf]>): string {
    const inner = entries
      .map(
        ([path, leaf]) =>
          '<ParameterValueStruct>' +
          `<Name>${esc(path)}</Name>` +
          `<Value${this.xsi(leaf.type)}>${esc(leaf.value)}</Value>` +
          '</ParameterValueStruct>',
      )
      .join('');
    const announced = this.opts.quirks?.arrayCountMismatch
      ? entries.length + 3
      : entries.length;
    return (
      `<ParameterList soap-enc:arrayType="cwmp:ParameterValueStruct[${announced}]">` +
      inner +
      '</ParameterList>'
    );
  }

  private informEnvelope(events: string[]): string {
    // THE SINGLE-ELEMENT-ARRAY QUIRK LIVES HERE. An Inform's ParameterList
    // normally carries six or more structs; a CPE with this quirk sends ONE,
    // and a parser without `isArray` turns it into an object instead of a
    // one-element list. Everything downstream that calls `.map()` throws.
    const paths = this.opts.quirks?.singleElementArray
      ? [`${this.root}DeviceInfo.SoftwareVersion`]
      : [
          `${this.root}DeviceInfo.HardwareVersion`,
          `${this.root}DeviceInfo.SoftwareVersion`,
          `${this.root}ManagementServer.ConnectionRequestURL`,
          `${this.root}ManagementServer.ParameterKey`,
          this.opts.dataModel === 'tr098'
            ? `${this.root}WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress`
            : `${this.root}IP.Interface.2.IPv4Address.1.IPAddress`,
        ];

    const entries: Array<[string, Leaf]> = paths
      .filter((p) => this.tree[p])
      .map((p) => [p, this.tree[p]]);

    const eventStructs = events
      .map((e) => `<EventStruct><EventCode>${esc(e)}</EventCode><CommandKey/></EventStruct>`)
      .join('');

    const body =
      '<cwmp:Inform>' +
      '<DeviceId>' +
      `<Manufacturer>${esc(this.tree[`${this.root}DeviceInfo.Manufacturer`].value)}</Manufacturer>` +
      `<OUI>${esc(this.opts.oui)}</OUI>` +
      (this.opts.productClass === null
        ? '' // the CPE that omits ProductClass entirely — a legal two-field id
        : `<ProductClass>${esc(this.opts.productClass ?? '')}</ProductClass>`) +
      `<SerialNumber>${esc(this.opts.serialNumber)}</SerialNumber>` +
      '</DeviceId>' +
      `<Event soap-enc:arrayType="cwmp:EventStruct[${events.length}]">${eventStructs}</Event>` +
      '<MaxEnvelopes>1</MaxEnvelopes>' +
      `<CurrentTime>${new Date().toISOString()}</CurrentTime>` +
      '<RetryCount>0</RetryCount>' +
      this.valueStructs(entries) +
      '</cwmp:Inform>';

    return this.envelope(`obliwan-fake-${Date.now()}`, body);
  }

  private transferCompleteEnvelope(
    commandKey: string,
    faultCode: string,
    faultString: string,
  ): string {
    const body =
      '<cwmp:TransferComplete>' +
      `<CommandKey>${esc(commandKey)}</CommandKey>` +
      `<FaultStruct><FaultCode>${esc(faultCode)}</FaultCode>` +
      `<FaultString>${esc(faultString)}</FaultString></FaultStruct>` +
      `<StartTime>${new Date(Date.now() - 60_000).toISOString()}</StartTime>` +
      `<CompleteTime>${new Date().toISOString()}</CompleteTime>` +
      '</cwmp:TransferComplete>';
    return this.envelope(`obliwan-fake-tc-${Date.now()}`, body);
  }

  // ── Answering the ACS ─────────────────────────────────────────────────────

  private answer(method: string, envelope: string, result: SessionResult): string {
    const id = extractTag(envelope, 'ID') ?? `resp-${Date.now()}`;
    switch (method) {
      case 'GetParameterValues':
        return this.answerGpv(envelope, id);
      case 'SetParameterValues':
        return this.answerSpv(envelope, id, result);
      case 'Download':
        return this.answerDownload(envelope, id);
      case 'Reboot':
        this.rebootCount++;
        return this.envelope(id, `<cwmp:RebootResponse></cwmp:RebootResponse>`);
      default:
        result.faultsSent.push('9000');
        return this.fault(id, '9000', `Method not supported: ${method}`);
    }
  }

  private answerGpv(envelope: string, id: string): string {
    const names = extractAll(envelope, 'string');
    const matched: Array<[string, Leaf]> = [];
    for (const name of names) {
      if (name.endsWith('.')) {
        // A PARTIAL PATH. This is the branch the whole learn-mode design rests
        // on: it returns the entire subtree, which is how an ACS discovers a
        // tree without GetParameterNames.
        for (const [path, leaf] of Object.entries(this.tree)) {
          if (path.startsWith(name)) matched.push([path, leaf]);
        }
      } else if (this.tree[name]) {
        matched.push([name, this.tree[name]]);
      }
    }
    if (names.length > 0 && matched.length === 0) {
      return this.fault(id, '9005', 'Invalid parameter name');
    }
    return this.envelope(
      id,
      `<cwmp:GetParameterValuesResponse>${this.valueStructs(matched)}` +
        '</cwmp:GetParameterValuesResponse>',
    );
  }

  private answerSpv(envelope: string, id: string, result: SessionResult): string {
    const names: string[] = [];
    const values: string[] = [];
    for (const m of envelope.matchAll(/<Name>([\s\S]*?)<\/Name>/g)) names.push(unesc(m[1]));
    for (const m of envelope.matchAll(/<Value[^>]*>([\s\S]*?)<\/Value>/g)) values.push(unesc(m[1]));

    if (this.opts.quirks?.echoRejectedValueInFault) {
      result.faultsSent.push('9007');
      return this.setValuesFault(id, names[0] ?? '', values[0] ?? '');
    }

    for (let i = 0; i < names.length; i++) {
      const path = names[i];
      const leaf = this.tree[path];
      if (!leaf) {
        result.faultsSent.push('9005');
        return this.fault(id, '9005', `Invalid parameter name: ${path}`);
      }
      if (!leaf.writable) {
        result.faultsSent.push('9008');
        return this.fault(id, '9008', `Non-writable parameter: ${path}`);
      }
      leaf.value = values[i] ?? '';
      this.setsApplied.push({ path, value: leaf.value });
    }
    return this.envelope(
      id,
      '<cwmp:SetParameterValuesResponse><Status>0</Status></cwmp:SetParameterValuesResponse>',
    );
  }

  private answerDownload(envelope: string, id: string): string {
    this.downloads.push({
      url: extractTag(envelope, 'URL') ?? '',
      commandKey: extractTag(envelope, 'CommandKey') ?? '',
      fileType: extractTag(envelope, 'FileType') ?? '',
    });
    // Status 1 = "the transfer has not completed, a TransferComplete will
    // follow". This is what makes the CommandKey correlation necessary, and
    // this client honours it: nothing else happens until `transferComplete()`.
    return this.envelope(
      id,
      '<cwmp:DownloadResponse><Status>1</Status>' +
        `<StartTime>${new Date().toISOString()}</StartTime>` +
        `<CompleteTime>${new Date(0).toISOString()}</CompleteTime>` +
        '</cwmp:DownloadResponse>',
    );
  }

  /**
   * The TR-069 shape of a refused write: a generic `cwmp:Fault` wrapper with a
   * `SetParameterValuesFault` per parameter inside it. Note what it does NOT
   * contain — a `<Value>` element — which is exactly why an ACS redactor that
   * keys on `<Name>`/`<Value>` adjacency walks straight past it.
   */
  private setValuesFault(id: string, path: string, value: string): string {
    return this.envelope(
      id,
      '<soap:Fault><faultcode>Client</faultcode><faultstring>CWMP fault</faultstring>' +
        '<detail><cwmp:Fault>' +
        '<FaultCode>9003</FaultCode>' +
        `<FaultString>${esc(`9007 rejected value ${value}`)}</FaultString>` +
        '<SetParameterValuesFault>' +
        `<ParameterName>${esc(path)}</ParameterName>` +
        '<FaultCode>9007</FaultCode>' +
        `<FaultString>${esc(`Invalid parameter value: ${value}`)}</FaultString>` +
        '</SetParameterValuesFault>' +
        '</cwmp:Fault></detail></soap:Fault>',
    );
  }

  private fault(id: string, code: string, message: string): string {
    return this.envelope(
      id,
      '<soap:Fault><faultcode>Client</faultcode><faultstring>CWMP fault</faultstring>' +
        '<detail><cwmp:Fault>' +
        `<FaultCode>${code}</FaultCode><FaultString>${esc(message)}</FaultString>` +
        '</cwmp:Fault></detail></soap:Fault>',
    );
  }

  // ── HTTP, with Digest and cookies done by hand ────────────────────────────

  private async post(body: string, result: SessionResult): Promise<Exchange> {
    let exchange = await this.rawPost(body, null);
    result.exchanges.push(exchange);

    // ONE retry on a challenge. A second 401 after we answered means either our
    // credentials are wrong or the ACS is looping, and a client that retried
    // forever would hide the second case behind a hang.
    if (exchange.status === 401) {
      result.authChallenges++;
      const challenge = parseChallenge(exchange.headers['www-authenticate']);
      if (!challenge) throw new Error('401 without a parseable WWW-Authenticate');
      this.lastChallenge = challenge;
      const auth = this.authorization(challenge);
      exchange = await this.rawPost(body, auth);
      result.exchanges.push(exchange);
    }

    if (exchange.headers['set-cookie']) result.cookieOffered = true;
    return exchange;
  }

  private authorization(challenge: Record<string, string>): string {
    const user = this.opts.username ?? '';
    const pass = this.opts.password ?? '';

    // THE `basicAuthOnly` QUIRK. Some carrier firmware only ever sends Basic,
    // whatever the ACS asked for. The ACS must reject it and say so, not loop.
    if (this.opts.quirks?.basicAuthOnly || (challenge.scheme ?? '').toLowerCase() === 'basic') {
      return 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');
    }

    this.nc++;
    const nc = this.nc.toString(16).padStart(8, '0');
    const uri = this.opts.path;
    const ha1 = md5(`${user}:${challenge.realm}:${pass}`);
    const ha2 = md5(`POST:${uri}`);
    const qop = challenge.qop?.split(',')[0].trim() || 'auth';
    const response = md5(
      `${ha1}:${challenge.nonce}:${nc}:${this.cnonce}:${qop}:${ha2}`,
    );
    return (
      `Digest username="${user}", realm="${challenge.realm}", nonce="${challenge.nonce}", ` +
      `uri="${uri}", qop=${qop}, nc=${nc}, cnonce="${this.cnonce}", response="${response}"` +
      (challenge.opaque ? `, opaque="${challenge.opaque}"` : '')
    );
  }

  private rawPost(body: string, authorization: string | null): Promise<Exchange> {
    return new Promise((resolve, reject) => {
      const headers: Record<string, string> = {
        // An EMPTY POST still carries Content-Length: 0 and a content type.
        // Dropping either is what makes some ACS implementations answer 411.
        'Content-Type': 'text/xml; charset=utf-8',
        'Content-Length': String(Buffer.byteLength(body, 'utf8')),
        'User-Agent': `ObliWAN-fakeCpe/${this.opts.dataModel}`,
      };
      if (authorization) headers.Authorization = authorization;
      // The `noCookie` quirk: never echo what the ACS set.
      if (this.cookie && !this.opts.quirks?.noCookie) headers.Cookie = this.cookie;

      const req = http.request(
        { host: this.opts.host, port: this.opts.port, path: this.opts.path, method: 'POST', headers },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => {
            const responseBody = Buffer.concat(chunks).toString('utf8');
            const setCookie = res.headers['set-cookie'];
            if (setCookie && !this.opts.quirks?.noCookie) {
              const acs = setCookie
                .map((c) => c.split(';')[0])
                .find((c) => c.startsWith('ACSsession='));
              if (acs) this.cookie = acs;
            }
            let xmlValid: boolean | null = null;
            let xmlError: string | undefined;
            if (responseBody.trim().length > 0) {
              const verdict = XMLValidator.validate(responseBody);
              xmlValid = verdict === true;
              if (verdict !== true) xmlError = verdict.err.msg;
            }
            if (this.opts.verbose) {
              console.log(`    -> ${res.statusCode} ${responseBody.slice(0, 300)}`);
            }
            resolve({
              requestBody: body,
              status: res.statusCode ?? 0,
              responseBody,
              headers: res.headers,
              xmlValid,
              xmlError,
            });
          });
        },
      );
      req.on('error', reject);
      req.setTimeout(15_000, () => req.destroy(new Error('fakeCpe: request timed out')));
      req.end(body);
    });
  }
}

// ============================================================================
// Tiny helpers — deliberately not a parser
// ============================================================================

function md5(input: string): string {
  return crypto.createHash('md5').update(input).digest('hex');
}

function esc(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function unesc(text: string): string {
  return text
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, '&');
}

/** First `<cwmp:Method>` in an ACS envelope, namespace prefix or not. */
export function firstRpcMethod(envelope: string): string | null {
  const m = /<(?:[A-Za-z0-9]+:)?(GetParameterValues|SetParameterValues|Download|Reboot|GetRPCMethods)\b/.exec(
    envelope,
  );
  return m ? m[1] : null;
}

function extractTag(xml: string, tag: string): string | null {
  const m = new RegExp(`<(?:[A-Za-z0-9]+:)?${tag}[^>]*>([\\s\\S]*?)</(?:[A-Za-z0-9]+:)?${tag}>`).exec(
    xml,
  );
  return m ? unesc(m[1].trim()) : null;
}

function extractAll(xml: string, tag: string): string[] {
  const out: string[] = [];
  const rx = new RegExp(`<(?:[A-Za-z0-9]+:)?${tag}[^>]*>([\\s\\S]*?)</(?:[A-Za-z0-9]+:)?${tag}>`, 'g');
  for (const m of xml.matchAll(rx)) out.push(unesc(m[1].trim()));
  return out;
}

/**
 * Parse a `WWW-Authenticate` header into its parameters.
 *
 * Written by hand rather than with a library because the point of this file is
 * to be an independent implementation, and because real CPE firmware parses it
 * exactly this loosely — which is precisely the behaviour the ACS has to be
 * robust against.
 */
export function parseChallenge(
  header: string | string[] | undefined,
): Record<string, string> | null {
  if (!header) return null;
  const raw = Array.isArray(header) ? header[0] : header;
  const schemeMatch = /^\s*(\w+)\s+/.exec(raw);
  if (!schemeMatch) return null;
  const out: Record<string, string> = { scheme: schemeMatch[1] };
  for (const m of raw.slice(schemeMatch[0].length).matchAll(/(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))/g)) {
    out[m[1].toLowerCase()] = m[2] ?? m[3];
  }
  return out;
}
