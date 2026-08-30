/**
 * ObliWAN — RouterOS `/export` tokenizer (layers L1 and L2).
 *
 * Implements N01, N04, N08, N12 and N13 of `docs/M4-normalisation-routeros.md`.
 *
 * SCOPE OF THIS FILE, AND ITS LIMIT. It turns text into `{sectionPath, verb,
 * props}` and does NOTHING semantic. It does not know what a firewall is, it
 * does not know that `/ip/firewall/filter` is ordered, and it never decides
 * that a value is uninteresting. Those are layer-3 decisions and they live in
 * `quirks.ts` (the doctrine) and `config/normalize.service.ts` (the engine).
 * Doctrine D3 of the study is exactly this: normalise as HIGH in the stack as
 * possible, because a regex over raw text does not know what it is eating.
 *
 * The only two things this file removes are the two the study allows at L1/L2:
 *
 *   N01  the `#` preamble — and it is PARSED BEFORE IT IS REMOVED, because it
 *        carries the OS version, the model and the serial. A `grep -v '^#'`
 *        would silently cost us upgrade detection, hardware-swap detection
 *        (a serial that changes at constant ppp_username is a replaced box)
 *        and any user comment rendered on a `#` line.
 *   N04  `.id` / `.nextid` — they are rank allocations in an internal table,
 *        they churn on every insert and every `move`, and a diff keyed on them
 *        reports three `changed` where one rule was inserted. They are dropped
 *        HERE so that it is structurally impossible for one to reach the NCM.
 *        `.id` remains indispensable at APPLY time (`/ip/firewall/filter/move`)
 *        but it is resolved then, on a fresh socket, and never read back from a
 *        snapshot (§N04 of the study).
 *
 * Everything else is preserved verbatim, including props we do not model — the
 * whitelist that drops them is L3 and it COUNTS what it dropped
 * (`unknownProps`), because a silent whitelist is a black hole and makes the
 * milestone's noise/false-negative ratio a lie (N05).
 */

import type { RawEntry } from '@obliwan/shared';

// ============================================================================
// Types
// ============================================================================

/**
 * The `#` header block. Two dialects exist and the study explicitly refuses to
 * state from memory which 7.1x release flipped the date format, so the parser
 * accepts both and records WHICH it saw rather than assuming.
 *
 *   RouterOS 6 : `# jan/02/2026 10:33:21 by RouterOS 6.49.10`
 *   RouterOS 7 : `# 2026-01-02 10:33:21 by RouterOS 7.14`
 */
export interface RouterOsPreamble {
  /** The raw `#` lines, kept so a future parser can re-derive more from them. */
  raw: string[];
  osVersion: string | null;
  model: string | null;
  serial: string | null;
  softwareId: string | null;
  /** The timestamp exactly as printed. NEVER parsed into a Date and never
   *  compared: it changes on every export and that is the point of N01. */
  exportedAt: string | null;
  dateStyle: 'ros6' | 'iso' | null;
  lineCount: number;
}

export const EMPTY_PREAMBLE: RouterOsPreamble = {
  raw: [],
  osVersion: null,
  model: null,
  serial: null,
  softwareId: null,
  exportedAt: null,
  dateStyle: null,
  lineCount: 0,
};

/**
 * One parsed line. Extends the study's `RawEntry` (§5.5) with the two RouterOS
 * shapes that a plain `props` map cannot express:
 *
 *   `set [ find default-name=ether1 ] name=wan`   -> `find`
 *   `set telnet disabled=yes`                     -> `positional`
 *
 * Both are identity, not payload: dropping them would make every `/ip/service`
 * line look like the same object and every `set [ find ]` line unattributable.
 */
export interface RouterOsEntry extends RawEntry {
  find: Record<string, string> | null;
  positional: string[];
  /** What L2 removed on this line (`.id`, `.nextid`). Kept for the trace, so
   *  "why is this rule not paired" has an answer that is not "read the code". */
  droppedProps: string[];
}

export interface ParsedExport {
  preamble: RouterOsPreamble;
  entries: RouterOsEntry[];
  /**
   * Human-readable acquisition problems. `warnings` is not decoration: a
   * continuation `\` in a `terse` export means a pty was allocated, and the
   * study is explicit that unfolding it silently masks a collector defect
   * instead of fixing it (N13).
   */
  warnings: string[];
  /** Lines the parser could not turn into an entry, with their index. A
   *  non-zero count here is a parser gap and must be visible, never absorbed. */
  unparsed: Array<{ line: number; text: string }>;
  /** Section paths seen, with how many lines each contributed. Feeds
   *  `NcmDocument.unmodeled[]` for everything the model does not cover — the
   *  declared-incompleteness of N5. */
  sectionLineCounts: Map<string, number>;
  stats: {
    totalLines: number;
    unfoldedLines: number;
    strayCommentLines: number;
  };
}

// ============================================================================
// L1 — text canonicalisation (N13)
// ============================================================================

/**
 * CRLF -> LF, trailing whitespace removed, trailing blank lines removed.
 *
 * DEBT: none. None of the three carries meaning in a RouterOS export, and all
 * three vary with the SSH client rather than with the configuration. A comment
 * whose value genuinely ends in a space is the one theoretical loss, and it is
 * inside quotes, where this function does not reach (it only trims the END of a
 * line, and a quoted value is never the last token without its closing quote).
 */
export function canonicalizeText(raw: string): string[] {
  return raw
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map((l) => l.replace(/[ \t]+$/, ''));
}

/**
 * Joins continuation lines. RouterOS wraps a long line with a trailing `\` and
 * indents the remainder when the output is a terminal.
 *
 * DEBT: none for the diff — but the CAUSE matters. `/export terse` on a channel
 * with no pty does not wrap, so a wrapped line means the collector allocated
 * one, which makes the terminal width an input to the hash for every device on
 * that path. The caller therefore gets a warning, and the fix is in the
 * transport, not here.
 */
export function unfoldLines(lines: readonly string[]): { lines: string[]; unfolded: number } {
  const out: string[] = [];
  let unfolded = 0;
  let acc: string | null = null;

  for (const line of lines) {
    const continues = endsWithContinuation(line);
    // Trailing whitespace before the backslash is KEPT. RouterOS wraps at the
    // terminal width, so the break can land right after a separating space; if
    // that space is stripped and the join adds none, two tokens fuse.
    const body = continues ? line.slice(0, -1) : line;
    if (acc === null) {
      acc = body;
    } else {
      // ┌─ RE-JOINED WITH NOTHING, NOT WITH A SPACE ────────────────────────┐
      // │ This used to insert one space. On a real export off a production  │
      // │ CHR that silently destroyed a value:                              │
      // │                                                                   │
      // │     script=\                                                      │
      // │         ":if ($bound=1) do={\                                     │
      // │                                                                   │
      // │ became `script= ":if …`, so the tokenizer read `script` as EMPTY  │
      // │ and turned the rest of the script into phantom properties         │
      // │ (`":if (\$bound` = `1) do={…`). The DHCP client's bind script —   │
      // │ two static routes re-pointed at the lease gateway, i.e. the       │
      // │ site's WAN failover — was parsed as nothing at all.                │
      // │                                                                   │
      // │ A `\`-continuation in RouterOS is a pure line break: the next     │
      // │ character continues the token. Only the READABILITY indentation   │
      // │ of the tail is an artifact, and only that is stripped.            │
      // │                                                                   │
      // │ This affected every wrapped value, not just scripts — and the     │
      // │ collector allocates a pty, so wrapping is the normal case.         │
      // └───────────────────────────────────────────────────────────────────┘
      acc = `${acc}${body.replace(/^[ \t]+/, '')}`;
      unfolded++;
    }
    if (!continues) {
      out.push(acc);
      acc = null;
    }
  }
  if (acc !== null) out.push(acc);
  return { lines: out, unfolded };
}

/** True when the line ends in an ODD number of backslashes: `a\\` is a literal
 *  backslash at end of value, `a\` is a wrap. */
function endsWithContinuation(line: string): boolean {
  let n = 0;
  for (let i = line.length - 1; i >= 0 && line[i] === '\\'; i--) n++;
  return n % 2 === 1;
}

// ============================================================================
// N01 — the preamble
// ============================================================================

const RE_HEADER_ROS7 = /^#\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+by\s+RouterOS\s+(\S+)/i;
const RE_HEADER_ROS6 = /^#\s*([a-z]{3}\/\d{1,2}\/\d{4}\s+\d{2}:\d{2}:\d{2})\s+by\s+RouterOS\s+(\S+)/i;
const RE_HEADER_KV = /^#\s*([a-z][a-z ]*?)\s*=\s*(.+?)\s*$/i;

/**
 * Consumes the CONTIGUOUS `#` block at the head of the file, up to the first
 * line starting with `/`. The double anchor (`^#` AND "before the first `/`")
 * is what makes N01 safe: a `#` line further down the file is NOT a header, and
 * this function will not touch it.
 */
export function parsePreamble(lines: readonly string[]): { preamble: RouterOsPreamble; rest: string[] } {
  const raw: string[] = [];
  let i = 0;
  for (; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === '') {
      // A blank line inside the header block is normal; a blank line before any
      // `#` is equally harmless. Neither terminates the preamble.
      if (raw.length === 0) continue;
      raw.push(line);
      continue;
    }
    if (line.startsWith('#')) { raw.push(line); continue; }
    break;
  }

  const preamble: RouterOsPreamble = { ...EMPTY_PREAMBLE, raw: raw.slice(), lineCount: raw.length };

  for (const line of raw) {
    const m7 = RE_HEADER_ROS7.exec(line);
    if (m7) {
      preamble.exportedAt = m7[1];
      preamble.osVersion = cleanVersionString(m7[2]);
      preamble.dateStyle = 'iso';
      continue;
    }
    const m6 = RE_HEADER_ROS6.exec(line);
    if (m6) {
      preamble.exportedAt = m6[1];
      preamble.osVersion = cleanVersionString(m6[2]);
      preamble.dateStyle = 'ros6';
      continue;
    }
    const kv = RE_HEADER_KV.exec(line);
    if (!kv) continue;
    const key = kv[1].trim().toLowerCase();
    const value = kv[2].trim();
    if (key === 'model') preamble.model = value || null;
    else if (key === 'serial number') preamble.serial = value || null;
    else if (key === 'software id') preamble.softwareId = value || null;
  }

  return { preamble, rest: lines.slice(i) };
}

/** `6.49.10` from `6.49.10`, `7.14` from `7.14 (stable)`. */
function cleanVersionString(raw: string): string | null {
  const m = /^v?([0-9][0-9a-zA-Z.\-_]*)/.exec(raw.trim());
  return m ? m[1] : null;
}

// ============================================================================
// L2 — tokenisation and unquoting (N08, N12)
// ============================================================================

/**
 * Splits a line into whitespace-separated tokens, respecting quotes and
 * backslash escapes. `[` and `]` are emitted as their own tokens so a
 * `set [ find … ]` selector can be recognised whatever the spacing.
 */
export function tokenize(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let started = false;
  let quote: '"' | "'" | null = null;

  const flush = (): void => {
    if (started) out.push(cur);
    cur = '';
    started = false;
  };

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      cur += ch;
      started = true;
      if (ch === '\\' && i + 1 < line.length) { cur += line[++i]; continue; }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; cur += ch; started = true; continue; }
    if (ch === '\\' && i + 1 < line.length) { cur += ch + line[++i]; started = true; continue; }
    if (ch === ' ' || ch === '\t') { flush(); continue; }
    if ((ch === '[' || ch === ']') && !started) { out.push(ch); continue; }
    if (ch === '[' || ch === ']') { flush(); out.push(ch); continue; }
    cur += ch;
    started = true;
  }
  if (quote) {
    // Unterminated quote: emit what we have rather than dropping the line. The
    // caller sees a prop with a stray quote, which is visible; a dropped line
    // is a `missing` finding on a rule that exists.
    flush();
  } else {
    flush();
  }
  return out;
}

/**
 * N12 — removes the quoting and the escaping, and normalises to Unicode NFC.
 *
 * RouterOS only quotes a value when it has to, and its heuristic changed
 * between versions and between `terse` and normal mode: `name=CPE-Lyon` on 6
 * and `name="CPE-Lyon"` on 7 are the same identity. The quoting therefore never
 * crosses L2, and no rule above this line has to care.
 *
 * DEBT: two comments differing ONLY by Unicode composition become identical
 * (`e` + combining acute vs precomposed `é`). No functional consequence — a
 * comment does not forward a packet — and the alternative is a `changed`
 * finding every time a technician edits a comment from a different keyboard
 * layout.
 */
export function unquote(value: string): string {
  let s = value;
  if (s.length >= 2 && ((s[0] === '"' && s[s.length - 1] === '"') || (s[0] === "'" && s[s.length - 1] === "'"))) {
    s = s.slice(1, -1);
  }
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch !== '\\' || i + 1 >= s.length) { out += ch; continue; }
    const next = s[++i];
    // AMBIGUITY IN THE ROUTEROS ESCAPE GRAMMAR, RESOLVED IN FAVOUR OF HEX.
    // `\a`, `\b` and `\f` are single-character escapes AND valid first halves
    // of a `\XX` byte escape, so `\b3` is either backspace + '3' or 0xB3. The
    // hex reading wins whenever a second hex digit follows: an accented
    // character in a comment or an interface name is common, and a literal bell
    // or backspace inside a configuration value is essentially never intended.
    // Getting this backwards costs a `low`-severity comment finding; it cannot
    // affect forwarding. Question left open by §7.4 — no device was available
    // to establish which form RouterOS actually emits.
    if (/[0-9a-fA-F]/.test(next) && i + 1 < s.length && /[0-9a-fA-F]/.test(s[i + 1])) {
      out += String.fromCharCode(parseInt(next + s[++i], 16));
      continue;
    }
    switch (next) {
      case 'n': out += '\n'; break;
      case 'r': out += '\r'; break;
      case 't': out += '\t'; break;
      case 'a': out += '\x07'; break;
      case 'b': out += '\b'; break;
      case 'f': out += '\f'; break;
      case 'v': out += '\v'; break;
      // RouterOS renders a space inside an unquoted value as `\_`.
      case '_': out += ' '; break;
      case '"': out += '"'; break;
      case "'": out += "'"; break;
      case '\\': out += '\\'; break;
      case '?': out += '?'; break;
      case '$': out += '$'; break;
      default:
        // `\XX` — a byte as two hex digits, which is how accented characters
        // come back on some versions.
        if (/[0-9a-fA-F]/.test(next) && i + 1 < s.length && /[0-9a-fA-F]/.test(s[i + 1])) {
          out += String.fromCharCode(parseInt(next + s[++i], 16));
        } else {
          out += next;
        }
    }
  }
  return out.normalize('NFC');
}

// ============================================================================
// Entry assembly
// ============================================================================

const VERBS = new Set(['add', 'set', 'remove', 'unset', 'print']);

/**
 * N04 — props that never cross the parser. Not a rule in the database on
 * purpose: a rule can be disabled, and there is no configuration in which
 * storing a `.id` is correct.
 */
const NEVER_STORED = new Set(['.id', '.nextid', '.dead', '.about', '.proplist']);

/** `/ip firewall filter` and `/ip/firewall/filter` both become
 *  `/ip/firewall/filter`. Never any space, never a trailing slash. */
export function canonicalSectionPath(words: readonly string[]): string {
  const parts: string[] = [];
  for (const w of words) {
    for (const p of w.split('/')) {
      const t = p.trim();
      if (t) parts.push(t.toLowerCase());
    }
  }
  return `/${parts.join('/')}`;
}

/**
 * Turns a `/export` into entries.
 *
 * Both renderings are accepted, because both exist in the wild and a fixture
 * captured through a different path must not produce a different NCM:
 *
 *   flat       `/ip firewall filter add action=accept chain=input`
 *   sectioned  `/ip firewall filter`  then  `add action=accept chain=input`
 */
export function parseExport(raw: string): ParsedExport {
  const warnings: string[] = [];
  const unparsed: Array<{ line: number; text: string }> = [];
  const sectionLineCounts = new Map<string, number>();

  const canonical = canonicalizeText(raw);
  const { lines, unfolded } = unfoldLines(canonical);
  if (unfolded > 0) {
    warnings.push(
      `export contained ${unfolded} continuation line(s) ending in "\\": the collector allocated a pty. ` +
        '`/export terse` on an exec channel without a pty does not wrap, and the terminal width must ' +
        'never be an input to ncm_hash (N13).',
    );
  }

  const { preamble, rest } = parsePreamble(lines);
  if (preamble.osVersion === null && preamble.lineCount > 0) {
    warnings.push('export preamble present but no "by RouterOS <version>" line was recognised (N01).');
  }

  const entries: RouterOsEntry[] = [];
  let currentSection: string | null = null;
  let strayCommentLines = 0;
  // Line numbers refer to the UNFOLDED text; the offset accounts for the
  // preamble we consumed. Good enough to point a human at the right rule and
  // honest about the fact that unfolding shifted the count.
  const offset = preamble.lineCount;

  for (let i = 0; i < rest.length; i++) {
    const text = rest[i];
    const lineNo = offset + i + 1;
    const trimmed = text.trim();
    if (trimmed === '') continue;

    if (trimmed.startsWith('#')) {
      // NOT a header: we are past the preamble. It is not an entry either, so
      // it is counted and reported rather than silently eaten.
      strayCommentLines++;
      continue;
    }

    if (trimmed.startsWith('/')) {
      const tokens = tokenize(trimmed);
      const verbIndex = findVerbIndex(tokens);
      if (verbIndex < 0) {
        // A bare menu path: a section header. `/ip firewall filter` with no
        // entries after it is N02 — an empty section, which the NCM represents
        // as an empty array and never as a difference.
        currentSection = canonicalSectionPath(tokens);
        bump(sectionLineCounts, currentSection, 0);
        continue;
      }
      const section = canonicalSectionPath(tokens.slice(0, verbIndex));
      const entry = buildEntry(section, tokens, verbIndex, lineNo);
      if (entry) { entries.push(entry); bump(sectionLineCounts, section, 1); }
      else unparsed.push({ line: lineNo, text: trimmed });
      // A flat line does NOT change the current section: RouterOS emits either
      // one form or the other, and letting a flat line set the section would
      // make a mixed file parse differently depending on line order.
      continue;
    }

    const tokens = tokenize(trimmed);
    if (tokens.length > 0 && VERBS.has(tokens[0]) && currentSection) {
      const entry = buildEntry(currentSection, tokens, 0, lineNo);
      if (entry) { entries.push(entry); bump(sectionLineCounts, currentSection, 1); }
      else unparsed.push({ line: lineNo, text: trimmed });
      continue;
    }

    unparsed.push({ line: lineNo, text: trimmed });
  }

  if (unparsed.length > 0) {
    warnings.push(
      `${unparsed.length} line(s) could not be parsed into an entry (first: line ${unparsed[0].line}). ` +
        'These are NOT absorbed: an unparsed line is a parser gap and it must be visible, ' +
        'otherwise the NCM claims a completeness it does not have (N3).',
    );
  }

  return {
    preamble,
    entries,
    warnings,
    unparsed,
    sectionLineCounts,
    stats: { totalLines: lines.length, unfoldedLines: unfolded, strayCommentLines },
  };
}

function bump(map: Map<string, number>, key: string, by: number): void {
  map.set(key, (map.get(key) ?? 0) + by);
}

/** Index of the verb token, or -1 for a bare section-header line. Path words
 *  are bare words; the verb is the first bare word that is a known verb. */
function findVerbIndex(tokens: readonly string[]): number {
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.includes('=')) return -1;      // props started: no verb on this line
    if (i > 0 && VERBS.has(t)) return i;
  }
  return -1;
}

function buildEntry(
  sectionPath: string,
  tokens: readonly string[],
  verbIndex: number,
  sourceLine: number,
): RouterOsEntry | null {
  const rawVerb = tokens[verbIndex];
  if (rawVerb === 'print' || rawVerb === 'unset') return null;
  const verb: RawEntry['verb'] =
    rawVerb === 'add' ? 'add' : rawVerb === 'remove' ? 'remove' : 'set';

  const props: Record<string, string> = {};
  const positional: string[] = [];
  const droppedProps: string[] = [];
  let find: Record<string, string> | null = null;

  for (let i = verbIndex + 1; i < tokens.length; i++) {
    const token = tokens[i];

    if (token === '[') {
      find = {};
      for (i++; i < tokens.length && tokens[i] !== ']'; i++) {
        const inner = tokens[i];
        if (inner === 'find' || inner === 'where') continue;
        const eq = inner.indexOf('=');
        if (eq > 0) find[inner.slice(0, eq)] = unquote(inner.slice(eq + 1));
      }
      continue;
    }

    // `!comment` — RouterOS's "unset this prop". An explicit empty value is a
    // different thing from an absent prop and is preserved as such.
    if (token.startsWith('!') && token.length > 1) {
      props[token.slice(1)] = '';
      continue;
    }

    const eq = token.indexOf('=');
    if (eq <= 0) { positional.push(unquote(token)); continue; }

    const key = token.slice(0, eq);
    if (NEVER_STORED.has(key)) { droppedProps.push(key); continue; }
    props[key] = unquote(token.slice(eq + 1));
  }

  return { sectionPath, verb, props, sourceLine, find, positional, droppedProps };
}
