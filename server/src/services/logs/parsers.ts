/**
 * ObliWAN — M8: turning a log line into "who opened a session on this box".
 *
 * PURE. No database, no clock, no I/O. Every function here takes a string and
 * returns either a structured login event or `null`, which makes the whole
 * per-brand vocabulary testable without a fleet — and there is no fleet: no
 * real MikroTik, DrayTek, Zyxel or SonicWall exists in this environment.
 *
 * ┌─ WHAT THAT MEANS FOR THE PATTERNS BELOW, STATED PLAINLY ─────────────────┐
 * │ The MikroTik family is transcribed from RouterOS' `system,info,account`   │
 * │ topic, whose wording is stable across 6.x and 7.x and is quoted verbatim  │
 * │ in the MikroTik documentation. The three other families are written from  │
 * │ published vendor syslog references, NOT from captures off a device we     │
 * │ own. They are therefore best-effort, and they are built to FAIL CLOSED:   │
 * │ a line that does not match completely returns `null` and stays an         │
 * │ ordinary log line. It never produces a half-parsed event with a guessed   │
 * │ account, because a guessed account becomes an accusation two screens      │
 * │ later.                                                                    │
 * │                                                                          │
 * │ The honest consequence: on DrayTek / Zyxel / SonicWall the expected       │
 * │ failure mode of M8 is `unattributed`, not "attributed to the wrong        │
 * │ person". That is the correct way for this to be wrong.                    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE SOURCE IP IN HERE IS NOT THE SOURCE IP OF THE DATAGRAM (A6) ────────┐
 * │ `ParsedLogin.sourceIp` is parsed out of the message TEXT and is the       │
 * │ address of the HUMAN who opened the session — an operator's workstation.  │
 * │ The datagram's peer address is the Docker bridge gateway and identifies   │
 * │ nothing. If you ever find yourself tempted to fall back on `rinfo.address`│
 * │ when this returns null, don't: an attribution to the gateway address is   │
 * │ a confident, plausible, entirely fictional answer.                        │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

import type { DeviceBrand } from '@obliwan/shared';
import { asInetOrNull } from '../fleet/concentratorDiscovery.service';
import type { LoginEventKind, LoginMethod } from './contract';

export interface ParsedLogin {
  event: LoginEventKind;
  account: string;
  method: LoginMethod;
  /** The operator's address, from the message body. Never the datagram's. */
  sourceIp: string | null;
}

/** A parser sees the message body and the syslog tag / RouterOS topic list. */
export type LoginParser = (message: string, tag: string | null) => ParsedLogin | null;

// ============================================================================
// Shared helpers
// ============================================================================

/**
 * Vendors decorate addresses in three different ways: `10.0.0.5:1044`,
 * `10.0.0.5:1044:X0` (SonicWall adds the interface), and `[2001:db8::1]:443`.
 * Strip the decoration, then let `asInetOrNull` be the judge — it already
 * refuses MAC addresses, which RouterOS puts in the same field shape.
 */
export function addressFrom(raw: string | null | undefined): string | null {
  if (!raw) return null;
  let v = raw.trim().replace(/[),;.]+$/, '');
  const bracketed = /^\[([0-9a-fA-F:]+)\](?::\d+)?$/.exec(v);
  if (bracketed) return asInetOrNull(bracketed[1]);
  // IPv4 with a port and possibly an interface suffix. Only strip when what is
  // in front looks like a dotted quad, so an IPv6 address is left alone.
  const v4 = /^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?::[\w.-]+)?$/.exec(v);
  if (v4) v = v4[1];
  return asInetOrNull(v);
}

/**
 * Map a vendor's word for a door onto our vocabulary.
 *
 * Returns `unknown` rather than a best guess. `unknown` costs the candidate
 * 0.10 of score; a wrong guess costs nothing and is silently wrong for ever.
 */
export function methodFrom(raw: string | null | undefined): LoginMethod {
  if (!raw) return 'unknown';
  const v = raw.trim().toLowerCase().replace(/[^a-z0-9-]/g, '');
  switch (v) {
    case 'winbox':
      return 'winbox';
    case 'ssh':
    case 'ssh2':
    case 'sftp':
      return 'ssh';
    case 'telnet':
      return 'telnet';
    case 'api':
    case 'apissl':
    case 'restapi':
      return 'api';
    case 'web':
    case 'webfig':
    case 'http':
    case 'https':
    case 'webui':
    case 'webconfigurator':
    case 'gui':
      return 'web';
    case 'ftp':
      return 'ftp';
    // RouterOS says `local` for a session opened on the box itself.
    case 'local':
    case 'console':
      return 'console';
    case 'serial':
    case 'tty':
      return 'serial';
    case 'vpn':
    case 'sslvpn':
    case 'l2tp':
    case 'pptp':
      return 'vpn';
    default:
      return 'unknown';
  }
}

/** `Account: admin,` / `usr="admin"` / `user=admin` — the labelled form three
 *  of the four brands use somewhere. */
function labelledValue(message: string, labels: string[]): string | null {
  for (const label of labels) {
    const re = new RegExp(`\\b${label}\\s*[:=]\\s*"?([^",;\\s]+)"?`, 'i');
    const m = re.exec(message);
    if (m && m[1].length > 0) return m[1];
  }
  return null;
}

function eventFromWording(message: string): LoginEventKind | null {
  const m = message.toLowerCase();
  // Order matters: "login failed" contains "login".
  if (/\b(fail(ed|ure)?|denied|incorrect|invalid|unsuccessful|reject(ed)?)\b/.test(m)) {
    return /\blog(in|ged|on|out)/.test(m) || /\bauth/.test(m) ? 'login_failed' : null;
  }
  if (/\blog(ged\s+out|out|off|ged\s+off)\b/.test(m)) return 'logout';
  if (/\blog(ged\s+in|in|on|ged\s+on)\b/.test(m)) return 'login';
  return null;
}

// ============================================================================
// MikroTik / RouterOS
// ============================================================================

/**
 * RouterOS emits these on the `system,info,account` topic, and the wording is
 * identical whether it reaches us as syslog or as a row of `/log`. That is why
 * one parser serves both paths and there is no second copy to drift from.
 *
 *   user admin logged in from 10.0.0.5 via winbox
 *   user admin logged out from 10.0.0.5 via winbox
 *   user admin logged in via local
 *   login failure for user admin from 10.0.0.5 via ssh
 */
const ROS_LOGIN =
  /^user\s+(\S+)\s+logged\s+in(?:\s+from\s+(\S+?))?(?:\s+via\s+(\S+))?\s*$/i;
const ROS_LOGOUT =
  /^user\s+(\S+)\s+logged\s+out(?:\s+from\s+(\S+?))?(?:\s+via\s+(\S+))?\s*$/i;
const ROS_FAILURE =
  /^login\s+failure\s+for\s+user\s+(\S+)(?:\s+from\s+(\S+?))?(?:\s+via\s+(\S+))?\s*$/i;

export const parseMikrotikLogin: LoginParser = (message) => {
  const text = message.trim();

  const failure = ROS_FAILURE.exec(text);
  if (failure) {
    return {
      event: 'login_failed',
      account: failure[1],
      method: methodFrom(failure[3]),
      sourceIp: addressFrom(failure[2]),
    };
  }
  const login = ROS_LOGIN.exec(text);
  if (login) {
    return {
      event: 'login',
      account: login[1],
      method: methodFrom(login[3]),
      sourceIp: addressFrom(login[2]),
    };
  }
  const logout = ROS_LOGOUT.exec(text);
  if (logout) {
    return {
      event: 'logout',
      account: logout[1],
      method: methodFrom(logout[3]),
      sourceIp: addressFrom(logout[2]),
    };
  }
  return null;
};

// ============================================================================
// Zyxel
// ============================================================================

/**
 * Zyxel ZyWALL / USG wording:
 *
 *   Administrator admin from 192.168.1.33 has logged in Web Configurator
 *   Administrator admin from 192.168.1.33 has logged out Web Configurator
 *   Failed login attempt to Device from ssh (incorrect password ...)
 *
 * UNVERIFIED against real hardware — see the file header.
 */
const ZYXEL_SESSION =
  /^(?:administrator|user)\s+(\S+)\s+from\s+(\S+)\s+has\s+logged\s+(in|out)\b\s*(.*)$/i;

export const parseZyxelLogin: LoginParser = (message) => {
  const text = message.trim();

  const session = ZYXEL_SESSION.exec(text);
  if (session) {
    return {
      event: session[3].toLowerCase() === 'out' ? 'logout' : 'login',
      account: session[1],
      // The trailing words are the channel ("Web Configurator", "SSH", "Console").
      method: methodFrom(session[4].replace(/\s+/g, '')),
      sourceIp: addressFrom(session[2]),
    };
  }

  // `Failed login attempt to Device from ssh (incorrect password ...)` is
  // deliberately NOT parsed: Zyxel does not print the attempted username on
  // that line, and an event with no account has nothing to attribute. There is
  // no pattern for it, rather than a pattern that fills in a placeholder.
  return null;
};

// ============================================================================
// DrayTek
// ============================================================================

/**
 * DrayTek Vigor labels its fields rather than writing a sentence:
 *
 *   [WEB]Login success from 192.168.1.10, Account: admin
 *   Vigor: Web login success. Account:admin, IP:192.168.1.10
 *   [TELNET]Login fail from 192.168.1.10, Account: admin
 *
 * UNVERIFIED against real hardware — see the file header.
 */
export const parseDraytekLogin: LoginParser = (message) => {
  const text = message.trim();
  if (!/\blog(in|out|ged)/i.test(text)) return null;

  const event = eventFromWording(text);
  if (!event) return null;

  const account = labelledValue(text, ['account', 'user', 'username']);
  if (!account) return null;

  const ip =
    labelledValue(text, ['ip', 'from', 'src', 'source']) ??
    (/\bfrom\s+(\S+)/i.exec(text)?.[1] ?? null);

  // `[WEB]` / `[TELNET]` / `(HTTPS)` prefix or suffix carries the channel.
  const channel = /[[(]\s*(WEB|HTTP|HTTPS|TELNET|SSH|FTP|CONSOLE|SERIAL)\s*[\])]/i.exec(text);

  return {
    event,
    account,
    method: methodFrom(channel?.[1]),
    sourceIp: addressFrom(ip),
  };
};

// ============================================================================
// SonicWall
// ============================================================================

/**
 * SonicOS syslog is a flat key=value record:
 *
 *   id=firewall sn=0017C5 time="..." fw=1.2.3.4 pri=5 c=1024 m=238
 *   msg="User login successful" n=7 src=192.168.168.20:1044:X0 usr="admin"
 *
 * UNVERIFIED against real hardware — see the file header.
 */
export const parseSonicwallLogin: LoginParser = (message) => {
  const text = message.trim();
  if (!/\busr\s*=/.test(text)) return null;

  const msg = /\bmsg\s*=\s*"([^"]*)"/i.exec(text)?.[1] ?? '';
  // The verdict comes from `msg=`, not from the whole record: `sess=` and
  // `note=` can carry words like "failed" about something else entirely.
  const event = eventFromWording(msg);
  if (!event) return null;

  const account = labelledValue(text, ['usr']);
  if (!account) return null;

  return {
    event,
    account,
    // SonicOS names the channel in `msg` ("GUI", "SSH") inconsistently across
    // firmware; when it is not there we say `unknown` rather than assume `web`.
    method: methodFrom(/\b(gui|web|https?|ssh|console|serial)\b/i.exec(msg)?.[1]),
    sourceIp: addressFrom(/\bsrc\s*=\s*(\S+)/i.exec(text)?.[1]),
  };
};

// ============================================================================
// Generic POSIX (sshd / dropbear)
// ============================================================================

/**
 * Every brand in the fleet ships some POSIX SSH daemon, and several of them log
 * through it rather than through their own subsystem. Applied as a fallback for
 * every brand — a match here is a genuine, unambiguous login line.
 */
const SSHD_ACCEPTED =
  /^Accepted\s+\S+\s+for\s+(\S+)\s+from\s+(\S+)(?:\s+port\s+\d+)?/i;
const SSHD_FAILED = /^Failed\s+\S+\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)/i;
const DROPBEAR_OK =
  /^(?:Password|Pubkey)\s+auth\s+succeeded\s+for\s+'([^']+)'\s+from\s+(\S+)/i;
const SSHD_CLOSED = /^(?:pam_unix\([^)]*\):\s*)?session\s+closed\s+for\s+user\s+(\S+)/i;

export const parseGenericLogin: LoginParser = (message, tag) => {
  const text = message.trim();
  // `sshd`, `dropbear`, `sshd[1234]` — the tag is the only thing that makes
  // these patterns safe to apply to every brand.
  if (tag && !/^(sshd|dropbear|login|sudo|pam_unix)\b/i.test(tag)) return null;

  const ok = SSHD_ACCEPTED.exec(text) ?? DROPBEAR_OK.exec(text);
  if (ok) {
    return { event: 'login', account: ok[1], method: 'ssh', sourceIp: addressFrom(ok[2]) };
  }
  const failed = SSHD_FAILED.exec(text);
  if (failed) {
    return {
      event: 'login_failed',
      account: failed[1],
      method: 'ssh',
      sourceIp: addressFrom(failed[2]),
    };
  }
  const closed = SSHD_CLOSED.exec(text);
  if (closed) {
    return { event: 'logout', account: closed[1], method: 'ssh', sourceIp: null };
  }
  return null;
};

// ============================================================================
// Dispatch
// ============================================================================

export const LOGIN_PARSERS: Readonly<Record<DeviceBrand, LoginParser>> = {
  mikrotik: parseMikrotikLogin,
  zyxel: parseZyxelLogin,
  draytek: parseDraytekLogin,
  sonicwall: parseSonicwallLogin,
};

/**
 * Try the brand's parser, then the POSIX fallback.
 *
 * When the brand is unknown (an unattributed message, or a device whose brand
 * has not been identified yet) EVERY parser is tried — but only one of them may
 * match. Two parsers claiming the same line means the line is ambiguous, and an
 * ambiguous login is the seed of a wrong attribution, so it is dropped.
 */
export function parseLoginLine(
  message: string,
  tag: string | null,
  brand: DeviceBrand | null,
): ParsedLogin | null {
  if (brand) {
    const parsed = LOGIN_PARSERS[brand](message, tag);
    if (parsed) return normalise(parsed);
    const generic = parseGenericLogin(message, tag);
    return generic ? normalise(generic) : null;
  }

  const hits: ParsedLogin[] = [];
  for (const parser of Object.values(LOGIN_PARSERS)) {
    const parsed = parser(message, tag);
    if (parsed) hits.push(parsed);
  }
  const generic = parseGenericLogin(message, tag);
  if (generic) hits.push(generic);
  return hits.length === 1 ? normalise(hits[0]) : null;
}

/** Trim and bound what a device sent. An account longer than the column is a
 *  malformed line, not a very long name — 128 is `device_login_events.account`. */
function normalise(parsed: ParsedLogin): ParsedLogin | null {
  const account = parsed.account.trim().replace(/[\u0000-\u001f\u007f]/g, '');
  if (account.length === 0 || account.length > 128) return null;
  return { ...parsed, account };
}

/**
 * RouterOS topic lists that carry account activity. Used by the `/log` puller
 * to ask for less, and by the syslog path to skip the regex work on the 99 % of
 * lines that are DHCP leases and interface flaps.
 *
 * Not a hard filter on the syslog path: a device may be configured to send
 * account messages under a different topic set, and the regexes fail closed
 * anyway.
 */
export const ROUTEROS_ACCOUNT_TOPICS = ['account', 'system'] as const;

export function looksLikeAccountTopic(tag: string | null): boolean {
  if (!tag) return false;
  const topics = tag.toLowerCase().split(/[,\s]+/);
  return ROUTEROS_ACCOUNT_TOPICS.some((t) => topics.includes(t));
}
