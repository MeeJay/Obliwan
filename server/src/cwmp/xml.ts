/**
 * ObliWAN — the CWMP wire format. The ONLY module that knows what a SOAP
 * envelope looks like.
 *
 * ┌─ WHY THE PARSER IS A LIBRARY AND THE SERIALISER IS NOT ───────────────────┐
 * │ INBOUND is hostile: it comes from firmware written by four vendors over    │
 * │ fifteen years, and it has to survive namespaces nobody declared, attribute │
 * │ spellings nobody agreed on and arrays that are not arrays. That is a       │
 * │ parsing problem and `fast-xml-parser` is better at it than we would be —   │
 * │ synchronously, which matters on a listener that may hold 300 sessions.     │
 * │                                                                           │
 * │ OUTBOUND is ours: five envelope shapes, all of them fixed. A generic       │
 * │ builder would be a configuration surface with no second user, and the      │
 * │ things that actually break CPEs — attribute ORDER, the `soap-enc:arrayType`│
 * │ count, whether `xsi:type` is present on a `Value` — are exactly the things │
 * │ a generic builder abstracts away. So: string templates, and every quirk    │
 * │ visible at the point where it matters.                                    │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ `isArray` IS NOT OPTIONAL, AND THIS IS THE BUG IT PREVENTS ──────────────┐
 * │ `fast-xml-parser` collapses a single repeated child into an OBJECT and a  │
 * │ repeated one into an ARRAY. A CPE that reports five parameters gives you  │
 * │ `ParameterValueStruct: [ {...} x5 ]`; the same CPE reporting one gives    │
 * │ you `ParameterValueStruct: {...}`. Every `.map()` downstream then throws  │
 * │ — on the exact devices that have the least to say, which are the ones     │
 * │ that just booted. `ARRAY_TAGS` below is what makes the shape stable, and  │
 * │ `fakeCpe`'s `singleElementArray` quirk is what proves it.                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * `parseTagValue: false` is the second non-negotiable: a serial number of
 * `0012345` must not become the number 12345, and `ConnectionStatus` of `1.0`
 * must not become `1`. Every CWMP value is a string until the data model says
 * otherwise, and the data model is `xsi:type`.
 */

import { XMLParser } from 'fast-xml-parser';
import {
  CWMP_FAULT,
  normaliseValueType,
  type CwmpFault,
  type CwmpValueType,
} from '@obliwan/shared/dist/cwmp';

// ============================================================================
// Parser
// ============================================================================

/**
 * Tags that are ALWAYS a list, whatever the CPE sent.
 *
 * `string` is in the list because `ParameterNames` in a `GetParameterValues`
 * is a `soap-enc:Array` of bare `<string>` elements, and a one-parameter read
 * is the common case.
 */
const ARRAY_TAGS = new Set([
  'ParameterValueStruct',
  'ParameterInfoStruct',
  'ParameterAttributeStruct',
  'EventStruct',
  'SetParameterValuesFault',
  'ArgStruct',
  'AccessList',
  'Notification',
  'string',
  'MethodList',
]);

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  // `soap:Envelope` -> `Envelope`, `xsi:type` -> `type`. CPEs invent prefixes
  // (`SOAP-ENV`, `s`, `soapenv`, none at all); matching on them is how an ACS
  // ends up with a per-vendor branch in its parser.
  removeNSPrefix: true,
  // NON-NEGOTIABLE. See the header.
  parseTagValue: false,
  parseAttributeValue: false,
  trimValues: true,
  // An empty `<Value/>` must be the empty STRING, not `true` and not `null`:
  // clearing a parameter is a legitimate value and the three are different
  // answers to the drift engine.
  allowBooleanAttributes: true,
  isArray: (tagName) => ARRAY_TAGS.has(tagName),
});

export type XmlNode = Record<string, unknown>;

/** What one inbound envelope amounts to, once the SOAP is gone. */
export interface ParsedEnvelope {
  /** The `cwmp:ID` SOAP header. Null when the CPE omitted it (a legal quirk). */
  id: string | null;
  /** The single child of `soap:Body`, e.g. `Inform`, `GetParameterValuesResponse`. */
  method: string | null;
  /** That child's contents. */
  body: XmlNode;
  /** Present when the CPE answered a fault instead of a response. */
  fault: CwmpFault | null;
  /** True when the CPE sent an envelope with no `cwmp:ID` — quirk `noCwmpId`. */
  missingId: boolean;
}

export class CwmpParseError extends Error {
  constructor(message: string, readonly snippet?: string) {
    super(message);
    this.name = 'CwmpParseError';
  }
}

/**
 * Parse an inbound envelope.
 *
 * Throws `CwmpParseError` rather than returning null: a body that arrived, was
 * not empty, and is not an envelope is a protocol error the ACS must answer
 * with a fault and record — silently returning null would make it look like an
 * empty POST, which is the one thing that MUST NOT be confused with an error.
 */
export function parseEnvelope(xml: string): ParsedEnvelope {
  let doc: XmlNode;
  try {
    doc = parser.parse(xml) as XmlNode;
  } catch (err) {
    throw new CwmpParseError(
      `not well-formed XML: ${err instanceof Error ? err.message : String(err)}`,
      xml.slice(0, 200),
    );
  }

  const envelope = asNode(doc.Envelope);
  if (!envelope) throw new CwmpParseError('no soap:Envelope', xml.slice(0, 200));

  const header = asNode(envelope.Header);
  const rawId = header ? header.ID : undefined;
  const id = rawId === undefined || rawId === null ? null : String(scalar(rawId)).trim();

  const bodyNode = asNode(envelope.Body);
  if (!bodyNode) throw new CwmpParseError('no soap:Body', xml.slice(0, 200));

  // A Fault is a Body child like any other; it is pulled out first because
  // callers branch on it and should not have to know its tag name.
  const faultNode = asNode(bodyNode.Fault);
  if (faultNode) {
    return {
      id: id || null,
      method: 'Fault',
      body: faultNode,
      fault: extractFault(faultNode),
      missingId: !id,
    };
  }

  const methodKeys = Object.keys(bodyNode).filter((k) => !k.startsWith('@_') && k !== '#text');
  if (methodKeys.length === 0) {
    throw new CwmpParseError('soap:Body is empty', xml.slice(0, 200));
  }
  const method = methodKeys[0];
  const body = asNode(bodyNode[method]) ?? {};

  return { id: id || null, method, body, fault: null, missingId: !id };
}

/**
 * Read a CWMP fault out of a `soap:Fault` node.
 *
 * The interesting code is NOT `faultcode` (always `Client` or `Server`) but the
 * `cwmp:Fault` inside `detail`, which is where `9005 Invalid parameter name`
 * lives. A CPE that omits `detail` gets `9002 Internal error` here, because
 * "something failed and the CPE would not say what" is closer to an internal
 * error than to a silence.
 */
function extractFault(faultNode: XmlNode): CwmpFault {
  const detail = asNode(faultNode.detail) ?? asNode(faultNode.Detail);
  const inner = detail ? asNode(detail.Fault) : null;

  const parameters: CwmpFault['parameters'] = [];
  if (inner) {
    const list = arrayOf(inner.SetParameterValuesFault);
    for (const item of list) {
      const node = asNode(item);
      if (!node) continue;
      parameters.push({
        path: text(node.ParameterName) ?? '',
        code: text(node.FaultCode) ?? CWMP_FAULT.INTERNAL_ERROR,
        faultString: text(node.FaultString) ?? '',
      });
    }
  }

  return {
    faultCode: text(faultNode.faultcode) ?? text(faultNode.Faultcode) ?? 'Client',
    code: (inner && text(inner.FaultCode)) || CWMP_FAULT.INTERNAL_ERROR,
    faultString:
      (inner && text(inner.FaultString)) ||
      text(faultNode.faultstring) ||
      'CPE returned a fault with no detail',
    ...(parameters.length > 0 ? { parameters } : {}),
  };
}

// ── Inform ──────────────────────────────────────────────────────────────────

export interface InformParameter {
  path: string;
  value: string;
  valueType: CwmpValueType;
  /** True when `xsi:type` was absent or unrecognised — quirk `badXsiType`. */
  typeWasBad: boolean;
}

export interface ParsedInform {
  manufacturer: string | null;
  oui: string;
  productClass: string | null;
  serialNumber: string;
  events: string[];
  /** Every `CommandKey` carried by an EventStruct — this is where an
   *  `M Download` announces which transfer it is about. */
  commandKeys: string[];
  currentTime: string | null;
  retryCount: number;
  maxEnvelopes: number;
  parameters: InformParameter[];
  /** The announced `soap-enc:arrayType` count vs. what actually arrived. */
  arrayCountMismatch: boolean;
}

export function parseInform(body: XmlNode): ParsedInform {
  const deviceId = asNode(body.DeviceId) ?? {};
  const eventWrapper = asNode(body.Event) ?? {};
  const eventStructs = arrayOf(eventWrapper.EventStruct);

  const events: string[] = [];
  const commandKeys: string[] = [];
  for (const raw of eventStructs) {
    const node = asNode(raw);
    if (!node) continue;
    const code = text(node.EventCode);
    if (code) events.push(code);
    const key = text(node.CommandKey);
    if (key) commandKeys.push(key);
  }

  const { parameters, mismatch } = parseParameterList(body.ParameterList);

  return {
    manufacturer: text(deviceId.Manufacturer),
    oui: (text(deviceId.OUI) ?? '').toUpperCase(),
    productClass: text(deviceId.ProductClass),
    serialNumber: text(deviceId.SerialNumber) ?? '',
    events,
    commandKeys,
    currentTime: text(body.CurrentTime),
    retryCount: int(body.RetryCount, 0),
    maxEnvelopes: int(body.MaxEnvelopes, 1),
    parameters,
    arrayCountMismatch: mismatch,
  };
}

/**
 * A `ParameterList` from anywhere — an Inform or a GetParameterValuesResponse.
 *
 * The `arrayType` count is compared against reality rather than trusted. A CPE
 * that announces 12 and sends 9 is not a parse failure (we take the 9), but it
 * IS a quirk worth recording: the next person debugging why three parameters
 * are missing deserves to find the answer as data instead of rediscovering it.
 */
export function parseParameterList(node: unknown): {
  parameters: InformParameter[];
  mismatch: boolean;
} {
  const wrapper = asNode(node);
  if (!wrapper) return { parameters: [], mismatch: false };

  const structs = arrayOf(wrapper.ParameterValueStruct);
  const parameters: InformParameter[] = [];

  for (const raw of structs) {
    const item = asNode(raw);
    if (!item) continue;
    const path = text(item.Name);
    if (!path) continue;

    // `Value` may be a scalar (`<Value>x</Value>`) or a node carrying the
    // attribute (`<Value xsi:type="xsd:string">x</Value>`). Both shapes come
    // out of the same firmware depending on whether the value is empty.
    const valueNode = item.Value;
    let rawType: string | null = null;
    let value = '';
    if (valueNode !== null && typeof valueNode === 'object') {
      const vn = valueNode as XmlNode;
      rawType = typeof vn['@_type'] === 'string' ? (vn['@_type'] as string) : null;
      value = vn['#text'] === undefined || vn['#text'] === null ? '' : String(vn['#text']);
    } else if (valueNode !== undefined && valueNode !== null) {
      value = String(valueNode);
    }

    const valueType = normaliseValueType(rawType);
    // "bad" means: absent, or present and not one of the eight canonical
    // spellings. `xsd:string` arriving as `string` counts as bad — it parsed,
    // but only because `normaliseValueType` covered for the CPE.
    const typeWasBad =
      rawType === null || !rawType.startsWith('xsd:') || normaliseValueType(rawType) !== rawType;

    parameters.push({ path, value, valueType, typeWasBad });
  }

  const announced = attrInt(wrapper['@_arrayType']);
  const mismatch = announced !== null && announced !== parameters.length;

  return { parameters, mismatch };
}

/** `cwmp:ParameterValueStruct[12]` -> 12. Null when there is no count. */
function attrInt(raw: unknown): number | null {
  if (typeof raw !== 'string') return null;
  const m = /\[(\d+)\]\s*$/.exec(raw);
  return m ? Number(m[1]) : null;
}

// ── Responses ───────────────────────────────────────────────────────────────

export interface ParsedTransferComplete {
  commandKey: string;
  faultCode: string;
  faultString: string;
  startTime: string | null;
  completeTime: string | null;
}

export function parseTransferComplete(body: XmlNode): ParsedTransferComplete {
  const fault = asNode(body.FaultStruct) ?? {};
  return {
    commandKey: text(body.CommandKey) ?? '',
    faultCode: text(fault.FaultCode) ?? '0',
    faultString: text(fault.FaultString) ?? '',
    startTime: text(body.StartTime),
    completeTime: text(body.CompleteTime),
  };
}

/** `SetParameterValuesResponse.Status`: 0 applied, 1 applied after reboot. */
export function parseSetStatus(body: XmlNode): number {
  return int(body.Status, 0);
}

// ============================================================================
// Serialiser — five shapes, written by hand
// ============================================================================

const NS =
  'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" ' +
  'xmlns:soap-enc="http://schemas.xmlsoap.org/soap/encoding/" ' +
  'xmlns:xsd="http://www.w3.org/2001/XMLSchema" ' +
  'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' +
  'xmlns:cwmp="urn:dslforum-org:cwmp-1-0"';

/**
 * Wrap a body.
 *
 * `mustUnderstand="1"` on `cwmp:ID` is what TR-069 requires and what makes a
 * CPE echo the id back on its response. Dropping it is legal and immediately
 * costs you request/response correlation on half the fleet.
 */
export function buildEnvelope(id: string, body: string): string {
  return (
    '<?xml version="1.0" encoding="UTF-8"?>' +
    `<soap:Envelope ${NS}>` +
    `<soap:Header><cwmp:ID soap:mustUnderstand="1">${escapeXml(id)}</cwmp:ID></soap:Header>` +
    `<soap:Body>${body}</soap:Body>` +
    '</soap:Envelope>'
  );
}

/**
 * The InformResponse.
 *
 * `MaxEnvelopes` is 1 and always will be: it tells the CPE how many envelopes
 * the ACS is willing to have in flight, and 1 is what makes the session a
 * strict request/response ping-pong. Anything higher buys throughput we do not
 * need on 300 CPEs and buys back a concurrency problem inside a single session.
 */
export function buildInformResponse(id: string): string {
  return buildEnvelope(id, '<cwmp:InformResponse><MaxEnvelopes>1</MaxEnvelopes></cwmp:InformResponse>');
}

export function buildTransferCompleteResponse(id: string): string {
  return buildEnvelope(id, '<cwmp:TransferCompleteResponse></cwmp:TransferCompleteResponse>');
}

/** The four methods of arbitrage A1, and nothing else. */
export function buildGetRpcMethodsResponse(id: string): string {
  const methods = ['Inform', 'TransferComplete', 'GetRPCMethods'];
  return buildEnvelope(
    id,
    '<cwmp:GetRPCMethodsResponse>' +
      `<MethodList soap-enc:arrayType="xsd:string[${methods.length}]">` +
      methods.map((m) => `<string>${escapeXml(m)}</string>`).join('') +
      '</MethodList></cwmp:GetRPCMethodsResponse>',
  );
}

export function buildGetParameterValues(id: string, paths: readonly string[]): string {
  return buildEnvelope(
    id,
    '<cwmp:GetParameterValues>' +
      `<ParameterNames soap-enc:arrayType="xsd:string[${paths.length}]">` +
      paths.map((p) => `<string>${escapeXml(p)}</string>`).join('') +
      '</ParameterNames></cwmp:GetParameterValues>',
  );
}

export interface SerialisableSetOp {
  path: string;
  valueType: CwmpValueType;
  /** RESOLVED value. For a secret parameter this is the plaintext from the
   *  vault and it exists only here, on the way to the socket (§8.2). */
  value: string;
}

/**
 * SetParameterValues.
 *
 * `ParameterKey` is the CPE's own change token: whatever we put here comes back
 * in the next Inform, which is how the ACS knows the box has actually taken the
 * write it was given. An empty one is legal and useless.
 */
export function buildSetParameterValues(
  id: string,
  ops: readonly SerialisableSetOp[],
  parameterKey = '',
): string {
  const structs = ops
    .map(
      (op) =>
        '<ParameterValueStruct>' +
        `<Name>${escapeXml(op.path)}</Name>` +
        `<Value xsi:type="${op.valueType}">${escapeXml(op.value)}</Value>` +
        '</ParameterValueStruct>',
    )
    .join('');
  return buildEnvelope(
    id,
    '<cwmp:SetParameterValues>' +
      `<ParameterList soap-enc:arrayType="cwmp:ParameterValueStruct[${ops.length}]">` +
      structs +
      '</ParameterList>' +
      `<ParameterKey>${escapeXml(parameterKey)}</ParameterKey>` +
      '</cwmp:SetParameterValues>',
  );
}

export interface DownloadArgs {
  commandKey: string;
  fileType: string;
  url: string;
  fileSize: number;
  targetFileName?: string;
  /** Seconds the CPE should wait before starting. 0 = immediately. */
  delaySeconds?: number;
}

/**
 * Download.
 *
 * `Username` and `Password` are sent EMPTY on purpose. The file server
 * authorises by an unguessable single-use token in the URL instead, because a
 * CPE behind carrier NAT fetching over plain HTTP would otherwise put a
 * reusable credential on the wire in clear, on a transit network, once per
 * firmware push (risk R9 and §8.2).
 */
export function buildDownload(id: string, args: DownloadArgs): string {
  return buildEnvelope(
    id,
    '<cwmp:Download>' +
      `<CommandKey>${escapeXml(args.commandKey)}</CommandKey>` +
      `<FileType>${escapeXml(args.fileType)}</FileType>` +
      `<URL>${escapeXml(args.url)}</URL>` +
      '<Username></Username>' +
      '<Password></Password>' +
      `<FileSize>${Math.max(0, Math.trunc(args.fileSize))}</FileSize>` +
      `<TargetFileName>${escapeXml(args.targetFileName ?? '')}</TargetFileName>` +
      `<DelaySeconds>${Math.max(0, Math.trunc(args.delaySeconds ?? 0))}</DelaySeconds>` +
      '<SuccessURL></SuccessURL>' +
      '<FailureURL></FailureURL>' +
      '</cwmp:Download>',
  );
}

export function buildReboot(id: string, commandKey: string): string {
  return buildEnvelope(
    id,
    `<cwmp:Reboot><CommandKey>${escapeXml(commandKey)}</CommandKey></cwmp:Reboot>`,
  );
}

/** A fault the ACS returns to the CPE — a malformed envelope, mostly. */
export function buildFault(id: string, code: string, message: string): string {
  return buildEnvelope(
    id,
    '<soap:Fault>' +
      '<faultcode>Client</faultcode>' +
      '<faultstring>CWMP fault</faultstring>' +
      '<detail><cwmp:Fault>' +
      `<FaultCode>${escapeXml(code)}</FaultCode>` +
      `<FaultString>${escapeXml(message)}</FaultString>` +
      '</cwmp:Fault></detail>' +
      '</soap:Fault>',
  );
}

// ============================================================================
// Helpers
// ============================================================================

export function escapeXml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function asNode(value: unknown): XmlNode | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as XmlNode)
    : null;
}

/**
 * Normalise a value that `isArray` should have made a list.
 *
 * A belt to `ARRAY_TAGS`'s braces: a tag we forgot to declare still degrades to
 * a one-element list here instead of throwing at the call site. The two are not
 * redundant — `ARRAY_TAGS` is what makes the SHAPE predictable for the type
 * system, this is what stops an omission from being a crash.
 */
function arrayOf(value: unknown): unknown[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function scalar(value: unknown): unknown {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const node = value as XmlNode;
    if ('#text' in node) return node['#text'];
  }
  return value;
}

function text(value: unknown): string | null {
  const s = scalar(value);
  if (s === undefined || s === null) return null;
  const out = String(s).trim();
  return out.length > 0 ? out : null;
}

function int(value: unknown, fallback: number): number {
  const s = text(value);
  if (s === null) return fallback;
  const n = Number.parseInt(s, 10);
  return Number.isFinite(n) ? n : fallback;
}
