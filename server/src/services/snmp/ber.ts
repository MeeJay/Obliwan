/**
 * A minimal, DEFENSIVE BER reader for inbound SNMP messages.
 *
 * WHY NOT `net-snmp`'s RECEIVER
 * `net-snmp` ships `createReceiver()`, but its type surface is declared in
 * `services/transport/net-snmp.d.ts` -- a file owned by another workstream and
 * covering the M2 client surface only. Rather than reach across a perimeter,
 * the trap listener owns its decoder. That turns out to be the better answer
 * anyway: this is the ONE place in the whole server where bytes arrive from an
 * UNAUTHENTICATED source on an open UDP port, and the decoder for that path
 * should be small enough to read in full.
 *
 * EVERY read is bounds-checked and every length is validated against the
 * buffer that actually arrived. A malformed datagram returns `null`; it never
 * throws past the caller, never allocates from a length field, and never
 * recurses without a depth budget. The threat model is not subtle: anyone who
 * can reach UDP/162 can send anything.
 */

/** Universal / application tags we decode. */
export const BER = {
  Integer: 0x02,
  OctetString: 0x04,
  Null: 0x05,
  OID: 0x06,
  Sequence: 0x30,
  IpAddress: 0x40,
  Counter32: 0x41,
  Gauge32: 0x42,
  TimeTicks: 0x43,
  Opaque: 0x44,
  Counter64: 0x46,
  NoSuchObject: 0x80,
  NoSuchInstance: 0x81,
  EndOfMibView: 0x82,
  /** Context-specific constructed PDU tags. */
  GetRequest: 0xa0,
  GetNextRequest: 0xa1,
  GetResponse: 0xa2,
  SetRequest: 0xa3,
  TrapV1: 0xa4,
  GetBulkRequest: 0xa5,
  InformRequest: 0xa6,
  TrapV2: 0xa7,
  Report: 0xa8,
} as const;

interface Tlv {
  tag: number;
  start: number;
  end: number;
  next: number;
}

/** Read one TLV at `offset`. Null on any inconsistency with the real buffer. */
export function readTlv(buf: Buffer, offset: number): Tlv | null {
  if (offset + 2 > buf.length) return null;
  const tag = buf[offset];
  let cursor = offset + 1;
  let length = buf[cursor];
  cursor += 1;

  if (length & 0x80) {
    const count = length & 0x7f;
    // A 5+ byte length means a value larger than any plausible datagram; a
    // zero-byte one is the indefinite form, which BER forbids here.
    if (count === 0 || count > 4 || cursor + count > buf.length) return null;
    length = 0;
    for (let i = 0; i < count; i += 1) {
      length = length * 256 + buf[cursor + i];
    }
    cursor += count;
  }

  const end = cursor + length;
  // THE CHECK THAT MATTERS: a declared length past the end of what was
  // actually received. Trusting it is how a decoder reads adjacent memory or
  // allocates a gigabyte from a 60-byte packet.
  if (length < 0 || end > buf.length) return null;
  return { tag, start: cursor, end, next: end };
}

/** Signed two's-complement integer. */
export function readInteger(buf: Buffer, tlv: Tlv): number | null {
  const len = tlv.end - tlv.start;
  if (len <= 0 || len > 8) return null;
  // Seeding with -1 when the sign bit is set is the standard trick: each
  // `value * 256 + byte` step then carries the sign correctly, so 0xFF reads
  // as -1 and 0xFF00 as -256 without a special case per width.
  let value = buf[tlv.start] & 0x80 ? -1 : 0;
  for (let i = tlv.start; i < tlv.end; i += 1) {
    value = value * 256 + buf[i];
  }
  return value;
}

/** Unsigned integer as a bigint (Counter32/64, Gauge32, TimeTicks). */
export function readUnsigned(buf: Buffer, tlv: Tlv): bigint | null {
  const len = tlv.end - tlv.start;
  if (len <= 0 || len > 9) return null;
  let value = 0n;
  for (let i = tlv.start; i < tlv.end; i += 1) {
    value = (value << 8n) | BigInt(buf[i]);
  }
  return value;
}

/** Dotted OID. The first byte packs the first two arcs as `40 * a + b`. */
export function readOid(buf: Buffer, tlv: Tlv): string | null {
  if (tlv.end <= tlv.start) return null;
  const first = buf[tlv.start];
  const arcs: number[] = [Math.floor(first / 40), first % 40];
  let acc = 0;
  let digits = 0;
  for (let i = tlv.start + 1; i < tlv.end; i += 1) {
    const byte = buf[i];
    acc = acc * 128 + (byte & 0x7f);
    digits += 1;
    // A sub-identifier longer than 5 base-128 digits exceeds 2^35 and is not
    // a real OID arc; refuse rather than silently overflow.
    if (digits > 5) return null;
    if ((byte & 0x80) === 0) {
      arcs.push(acc);
      acc = 0;
      digits = 0;
    }
  }
  // A trailing continuation bit means the OID was truncated mid-arc.
  if (digits !== 0) return null;
  return arcs.join('.');
}

export interface DecodedVarbind {
  oid: string;
  type: number;
  value: string | number | bigint | null;
}

function readValue(buf: Buffer, tlv: Tlv): string | number | bigint | null {
  switch (tlv.tag) {
    case BER.Integer:
      return readInteger(buf, tlv);
    case BER.Counter32:
    case BER.Gauge32:
    case BER.TimeTicks:
    case BER.Counter64:
      return readUnsigned(buf, tlv);
    case BER.OID:
      return readOid(buf, tlv);
    case BER.IpAddress:
      return tlv.end - tlv.start === 4 ? Array.from(buf.subarray(tlv.start, tlv.end)).join('.') : null;
    case BER.Null:
    case BER.NoSuchObject:
    case BER.NoSuchInstance:
    case BER.EndOfMibView:
      return null;
    case BER.OctetString:
    default:
      // Text from a device is UNTRUSTED. Control bytes are stripped and the
      // length is capped: a 60 KB "hostname" would otherwise travel into a
      // jsonb column and out to a browser.
      return buf
        .subarray(tlv.start, Math.min(tlv.end, tlv.start + 4096))
        .toString('utf8')
        .replace(/[\u0000-\u001f\u007f]/g, '');
  }
}

/** Decode a `SEQUENCE OF VarBind`. Caps the count: a datagram cannot legitimately
 *  carry thousands, and an unbounded loop here is a free CPU sink. */
function readVarbinds(buf: Buffer, seq: Tlv, max = 256): DecodedVarbind[] {
  const out: DecodedVarbind[] = [];
  let cursor = seq.start;
  while (cursor < seq.end && out.length < max) {
    const pair = readTlv(buf, cursor);
    if (!pair || pair.tag !== BER.Sequence) break;
    const oidTlv = readTlv(buf, pair.start);
    if (!oidTlv || oidTlv.tag !== BER.OID) break;
    const valueTlv = readTlv(buf, oidTlv.next);
    if (!valueTlv) break;
    const oid = readOid(buf, oidTlv);
    if (oid) out.push({ oid, type: valueTlv.tag, value: readValue(buf, valueTlv) });
    cursor = pair.next;
  }
  return out;
}

export interface DecodedTrap {
  /** 0 = v1, 1 = v2c, 3 = v3. */
  version: number;
  community: string | null;
  pduTag: number;
  varbinds: DecodedVarbind[];
  /** v1 only. */
  enterprise: string | null;
  agentAddr: string | null;
  genericTrap: number | null;
  specificTrap: number | null;
  /** sysUpTime carried by the trap, in TimeTicks. */
  uptimeTicks: bigint | null;
  /** v2c: the value of the `snmpTrapOID.0` varbind. v1: synthesised from
   *  enterprise + generic/specific, per RFC 3584 section 3.1. */
  trapOid: string | null;
}

const SNMP_TRAP_OID = '1.3.6.1.6.3.1.1.4.1.0';
const SYS_UPTIME_OID = '1.3.6.1.2.1.1.3.0';

/**
 * RFC 3584 section 3.1 -- how a v1 trap is named in v2c terms.
 *
 * generic 0..5 map onto `1.3.6.1.6.3.1.1.5.{generic+1}`; generic 6
 * (enterpriseSpecific) becomes `<enterprise>.0.<specific>`. Without this a v1
 * trap and the v2c trap describing the SAME event carry different identities,
 * and no rule written for one ever matches the other.
 */
function v1TrapOid(enterprise: string | null, generic: number, specific: number): string {
  if (generic >= 0 && generic <= 5) return `1.3.6.1.6.3.1.1.5.${generic + 1}`;
  return enterprise ? `${enterprise}.0.${specific}` : `0.0.${specific}`;
}

/**
 * Decode an inbound SNMP trap/inform datagram. `null` on anything malformed.
 *
 * SNMPv3 is decoded only far enough to report its version. A v3 trap is
 * authenticated and possibly encrypted through USM, which needs the engine ID
 * and the user's keys; accepting one without verifying that would be strictly
 * worse than refusing it, because it would look authenticated on screen.
 */
export function decodeTrap(buf: Buffer): DecodedTrap | null {
  const message = readTlv(buf, 0);
  if (!message || message.tag !== BER.Sequence) return null;

  const versionTlv = readTlv(buf, message.start);
  if (!versionTlv || versionTlv.tag !== BER.Integer) return null;
  const version = readInteger(buf, versionTlv);
  if (version === null) return null;

  if (version === 3) {
    return {
      version: 3,
      community: null,
      pduTag: 0,
      varbinds: [],
      enterprise: null,
      agentAddr: null,
      genericTrap: null,
      specificTrap: null,
      uptimeTicks: null,
      trapOid: null,
    };
  }

  const communityTlv = readTlv(buf, versionTlv.next);
  if (!communityTlv || communityTlv.tag !== BER.OctetString) return null;
  const community = buf
    .subarray(communityTlv.start, Math.min(communityTlv.end, communityTlv.start + 256))
    .toString('utf8');

  const pdu = readTlv(buf, communityTlv.next);
  if (!pdu) return null;

  if (pdu.tag === BER.TrapV1) {
    const entTlv = readTlv(buf, pdu.start);
    if (!entTlv) return null;
    const addrTlv = readTlv(buf, entTlv.next);
    if (!addrTlv) return null;
    const genTlv = readTlv(buf, addrTlv.next);
    if (!genTlv) return null;
    const specTlv = readTlv(buf, genTlv.next);
    if (!specTlv) return null;
    const timeTlv = readTlv(buf, specTlv.next);
    if (!timeTlv) return null;
    const vbTlv = readTlv(buf, timeTlv.next);

    const enterprise = readOid(buf, entTlv);
    const generic = readInteger(buf, genTlv) ?? 6;
    const specific = readInteger(buf, specTlv) ?? 0;
    return {
      version,
      community,
      pduTag: pdu.tag,
      varbinds: vbTlv && vbTlv.tag === BER.Sequence ? readVarbinds(buf, vbTlv) : [],
      enterprise,
      agentAddr:
        addrTlv.end - addrTlv.start === 4
          ? Array.from(buf.subarray(addrTlv.start, addrTlv.end)).join('.')
          : null,
      genericTrap: generic,
      specificTrap: specific,
      uptimeTicks: readUnsigned(buf, timeTlv),
      trapOid: v1TrapOid(enterprise, generic, specific),
    };
  }

  if (pdu.tag !== BER.TrapV2 && pdu.tag !== BER.InformRequest) return null;

  // v2c PDU: request-id, error-status, error-index, varbinds.
  const reqTlv = readTlv(buf, pdu.start);
  if (!reqTlv) return null;
  const errTlv = readTlv(buf, reqTlv.next);
  if (!errTlv) return null;
  const idxTlv = readTlv(buf, errTlv.next);
  if (!idxTlv) return null;
  const vbTlv = readTlv(buf, idxTlv.next);
  if (!vbTlv || vbTlv.tag !== BER.Sequence) return null;

  const varbinds = readVarbinds(buf, vbTlv);
  const uptime = varbinds.find((v) => v.oid === SYS_UPTIME_OID);
  const trapOid = varbinds.find((v) => v.oid === SNMP_TRAP_OID);

  return {
    version,
    community,
    pduTag: pdu.tag,
    varbinds,
    enterprise: null,
    agentAddr: null,
    genericTrap: null,
    specificTrap: null,
    uptimeTicks: typeof uptime?.value === 'bigint' ? uptime.value : null,
    trapOid: typeof trapOid?.value === 'string' ? trapOid.value : null,
  };
}
