/* eslint-disable @typescript-eslint/no-explicit-any */
import { parentPort, workerData } from 'worker_threads';
import vm from 'vm';

/**
 * renderWorker.ts — THE PRISON (risk R6).
 *
 * ┌───────────────────────────────────────────────────────────────────────────┐
 * │ WHY THIS FILE IS SHAPED THE WAY IT IS                                     │
 * │                                                                           │
 * │ Nunjucks does not sandbox anything. `{{ x.constructor.constructor(...) }}` │
 * │ reaches the `Function` constructor of whatever realm the compiled template │
 * │ runs in, and from there the realm's globals. The process that evaluates    │
 * │ these templates is the process that holds the administrative credentials   │
 * │ of every device of every client. An escape here is not a local privilege   │
 * │ escalation — it is handing over every network we manage.                   │
 * │                                                                           │
 * │ So the template does NOT run in this file's realm. It runs inside a        │
 * │ `vm` context that contains nothing but ECMAScript intrinsics: no           │
 * │ `process`, no `require`, no `fetch`, no `Buffer`, no `setTimeout`, no      │
 * │ `console`, no module record, and therefore nothing to escape TO. Nunjucks  │
 * │ itself is loaded INTO that realm, from its browser bundle, as source text  │
 * │ handed over by the parent thread — which is why this worker never opens a  │
 * │ file, never resolves a module and never touches the database.              │
 * │                                                                           │
 * │ FOUR LAYERS, and each one is there because the one above it can fail:      │
 * │                                                                           │
 * │  1. `vm` realm      — removes the escape target. `Function('return         │
 * │                       process')()` evaluates in the sandbox realm and      │
 * │                       yields `undefined`, because the sandbox realm has no │
 * │                       `process`. This is the layer that actually stops     │
 * │                       R6; the other three exist for when it does not.      │
 * │  2. `vm` timeout    — `runInContext(..., { timeout })` interrupts a        │
 * │                       synchronous infinite loop from V8 itself, INSIDE the │
 * │                       thread, and lets the next job proceed.               │
 * │  3. worker thread   — `resourceLimits` caps the heap, so a runaway         │
 * │                       allocation kills this thread and nothing else; the   │
 * │                       parent's watchdog terminates it if it stops          │
 * │                       answering at all.                                    │
 * │  4. JSON-only wire  — nothing but strings crosses in either direction.     │
 * │                       No live object, no function, no prototype from the   │
 * │                       server realm ever enters the sandbox, so there is no │
 * │                       host object whose `.constructor` could be walked     │
 * │                       back out. `console` is deleted from the sandbox for  │
 * │                       exactly this reason: Node contextifies it per        │
 * │                       context, but it is the kind of object that stops     │
 * │                       being contextified the day somebody "optimises" it.  │
 * │                                                                           │
 * │ KNOWN, MEASURED, AND NOT FIXED HERE — `resourceLimits` DOES NOT COVER A   │
 * │ SINGLE OVERSIZED ALLOCATION. Node turns a worker heap that grows          │
 * │ GRADUALLY past its ceiling into a catchable ERR_WORKER_OUT_OF_MEMORY on   │
 * │ the parent's `error` event (verified: a loop pushing 1 M-element arrays   │
 * │ is caught, the API process is untouched). ONE allocation that overshoots  │
 * │ the ceiling in a single step reaches V8's fatal handler instead and       │
 * │ aborts THE WHOLE PROCESS. Reproduced on Node 24.14 with no ObliWAN code   │
 * │ involved at all:                                                          │
 * │                                                                           │
 * │   new Worker('new Array(100000000).fill(7)', { eval: true,               │
 * │     resourceLimits: { maxOldGenerationSizeMb: 64, ... } })                │
 * │   -> FATAL ERROR: Reached heap limit — the parent dies with it.           │
 * │                                                                           │
 * │ Two mitigations below cover the paths a template reaches WITHOUT an       │
 * │ escape, which is to say the paths an ordinary author reaches by accident: │
 * │ `range()` is bounded (nunjucks materialises its array, so                 │
 * │ `{% for i in range(0, 1e8) %}` WAS exactly this bug, one typo away), and  │
 * │ no interpolated value may exceed 1 MiB — checked on `.length` before any  │
 * │ regex, so a rope is never flattened into one huge allocation.             │
 * │                                                                           │
 * │ What remains uncovered is a DELIBERATELY hostile template that reaches    │
 * │ `Function` and allocates in one step. That costs availability, not        │
 * │ secrecy — the realm still has no credentials, no database, no network —   │
 * │ and it costs it to somebody who already holds `TEMPLATE_WRITE`. Closing   │
 * │ it needs process isolation (`child_process.fork` with                     │
 * │ `--max-old-space-size`), a deviation from the mandated `worker_threads`   │
 * │ design and therefore an arbitration for the lead, not a decision to take  │
 * │ quietly inside this file.                                                 │
 * │                                                                           │
 * │ KNOWN, MEASURED, AND ACCEPTED: a template that reaches `Function` can call │
 * │ `import('node:fs')`. In a `vm` context with no dynamic-import callback,    │
 * │ V8 asks Node for one, Node has none, and it raises                         │
 * │ ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING — asynchronously, from a microtask, │
 * │ where no `try/catch` around `runInContext` can see it. The module is NOT   │
 * │ loaded (fail-closed), but the throw is uncatchable at the call site, so it │
 * │ would tear down the thread. `process.on('uncaughtException')` below turns  │
 * │ that into a reported render failure and a clean exit instead of a silent   │
 * │ dead worker. The observed behaviour is in the milestone report.            │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

// ── The wire, and it is deliberately made of strings ────────────────────────

export interface RenderWorkerJob {
  id: string;
  entry: string;
  /** loader name -> template source. The ONLY thing the sandbox loader knows. */
  sources: Record<string, string>;
  /** JSON text. Never an object: see layer 4. */
  contextJson: string;
  options: {
    autoescape: boolean;
    throwOnUndefined: boolean;
    trimBlocks: boolean;
    lstripBlocks: boolean;
  };
}

export interface RenderWorkerInput {
  /** Source text of `nunjucks/browser/nunjucks.js`, read by the PARENT. */
  bundleSource: string;
  jobs: RenderWorkerJob[];
  timeoutMs: number;
  maxOutputBytes: number;
}

export type RenderWorkerErrorKind =
  | 'template'   // the template itself is wrong (syntax, missing partial, filter refusal)
  | 'timeout'    // layer 2 fired
  | 'output_too_large'
  | 'sandbox'    // the sandbox could not be built — our bug, never the author's
  | 'internal';

export type RenderWorkerMessage =
  | {
      type: 'result';
      id: string;
      ok: boolean;
      output: string | null;
      errorKind: RenderWorkerErrorKind | null;
      errorMessage: string | null;
      durationMs: number;
    }
  | { type: 'fatal'; message: string; kind: RenderWorkerErrorKind }
  | { type: 'done' };

// ============================================================================
// THE SANDBOX PROGRAM
// ============================================================================
//
// Everything below runs INSIDE the vm realm. It is a string on purpose: a
// function value passed into the context would carry this realm's `Function`
// on its `.constructor`, which is precisely the escape the whole file exists to
// prevent. Filters, the loader and the escaper are therefore defined in the
// sandbox's own realm, from source.
//
// Contains no backtick and no `${` so that it survives being a template
// literal. Written in ES5 style for the same reason it is a string: it is
// evaluated by V8 directly, never by TypeScript.

export const SANDBOX_PROGRAM = `
(function () {
  'use strict';

  var nunjucks = globalThis.nunjucks;

  // ── Shrink the realm ──────────────────────────────────────────────────────
  // Nothing here is an escape on its own inside a vm context; every deletion is
  // surface removed rather than a hole closed. 'nunjucks' goes too: a template
  // that reached it could put the HTML escaper back and undo the RouterOS
  // escaping installed below.
  delete globalThis.nunjucks;
  delete globalThis.console;
  delete globalThis.SharedArrayBuffer;
  delete globalThis.Atomics;
  delete globalThis.WebAssembly;
  delete globalThis.Intl;
  delete globalThis.self;

  var hasOwn = Object.prototype.hasOwnProperty;

  function Refusal(message) {
    var e = new Error(message);
    e.owRefusal = true;
    return e;
  }

  // ==========================================================================
  // RouterOS escaping — treated as a security boundary, like SQL.
  // ==========================================================================
  //
  // Two shapes, and the choice between them is made by the VALUE, not by the
  // author:
  //
  //   * a value made only of characters that cannot change the meaning of a
  //     RouterOS command is emitted verbatim. That keeps the natural template
  //     readable: 'address={{ ip }}/{{ prefix }}' still produces
  //     'address=10.0.0.1/24'.
  //   * anything else is emitted as a quoted RouterOS string. If the author was
  //     concatenating around it, the command breaks LOUDLY instead of silently
  //     gaining a second command, a negation or a command substitution.
  //
  // The bare set deliberately EXCLUDES, and each exclusion is a real attack:
  //   space ; \\n   -> terminates the command and starts another
  //   " \\\\ $ ?      -> string, escape and substitution syntax
  //   [ ]          -> RouterOS command substitution: [/interface find ...]
  //   !            -> RouterOS negation: 'src-address=!10.0.0.0/8' inverts a
  //                   firewall match, which is an injection that changes the
  //                   MEANING of a rule without adding one
  //   ,            -> multi-value syntax: '1.2.3.4,0.0.0.0/0' widens a rule
  //   = < > ~      -> parameter and comparison syntax
  //   ( ) { }      -> grouping and blocks
  var SAFE_BARE = /^[A-Za-z0-9_.:\\/+@-]+$/;

  /** No RouterOS parameter is a megabyte long. See the comment in rosValue. */
  var MAX_VALUE_CHARS = 1048576;

  /**
   * Nunjucks' 'range' MATERIALISES an array: '{% for i in range(0, 1e8) %}' is
   * an 800 MB allocation, and a single allocation that overshoots the worker's
   * heap ceiling in one step aborts the whole PROCESS instead of raising
   * ERR_WORKER_OUT_OF_MEMORY in the thread (measured on Node 24; the graceful
   * path only covers heaps that grow gradually). This bound is therefore not
   * tidiness — it is what keeps the realistic version of that mistake, a typo
   * in a loop bound, from taking the API down. It is enforced INSIDE the realm
   * because a template can reach 'range' and cannot reach anything of ours.
   */
  var MAX_RANGE = 100000;

  function hex2(n) {
    var s = n.toString(16).toUpperCase();
    return s.length === 1 ? '0' + s : s;
  }

  /** Escape the interior of a RouterOS double-quoted string. */
  function escapeQuotedBody(s) {
    var out = '';
    for (var i = 0; i < s.length; i++) {
      var ch = s.charAt(i);
      var code = s.charCodeAt(i);
      if (ch === '\\\\') { out += '\\\\\\\\'; }
      else if (ch === '"') { out += '\\\\"'; }
      else if (ch === '$') { out += '\\\\$'; }         // variable substitution
      else if (ch === '?') { out += '\\\\?'; }         // console wildcard
      else if (ch === '\\n') { out += '\\\\n'; }
      else if (ch === '\\r') { out += '\\\\r'; }
      else if (ch === '\\t') { out += '\\\\t'; }
      // '[' and ']' are hex-escaped rather than left literal. Whether RouterOS
      // performs command substitution inside a quoted string is not something
      // we can verify without a device, and the failure mode of being wrong in
      // this direction is a broken command; the failure mode of being wrong in
      // the other direction is arbitrary command execution on the router.
      else if (ch === '[') { out += '\\\\5B'; }
      else if (ch === ']') { out += '\\\\5D'; }
      else if (code < 0x20 || code === 0x7f) { out += '\\\\' + hex2(code); }
      else { out += ch; }
    }
    return out;
  }

  /**
   * The one function every interpolated value goes through, including via
   * autoescape. Refuses rather than guesses: a null, an object or a NaN that
   * reaches a RouterOS command line is a bug in the caller, and turning it into
   * 'null' or '[object Object]' would put that bug on a router.
   */
  function rosValue(v) {
    if (v === null || v === undefined) {
      throw Refusal('RouterOS escaping refused a null/undefined value');
    }
    if (typeof v === 'boolean') return v ? 'yes' : 'no';
    if (typeof v === 'number') {
      if (!isFinite(v)) throw Refusal('RouterOS escaping refused a non-finite number');
      return String(v);
    }
    if (typeof v === 'string') {
      // Checked BEFORE the regex, and the order is the point: reading .length
      // on a rope is free, running a regex over it FLATTENS it. A template that
      // built a 128 MB string by doubling would otherwise force a single huge
      // allocation right here — and a single allocation that overshoots the
      // worker's heap ceiling in one step is process-fatal in V8, not a caught
      // worker error (measured; see the milestone report).
      if (v.length > MAX_VALUE_CHARS) {
        throw Refusal(
          'RouterOS escaping refused a value of ' + v.length + ' characters (limit ' +
          MAX_VALUE_CHARS + '): no RouterOS parameter is that long'
        );
      }
      if (v.length === 0) return '""';
      if (SAFE_BARE.test(v)) return v;
      return '"' + escapeQuotedBody(v) + '"';
    }
    if (v && typeof v.val === 'string' && v.length !== undefined) {
      // nunjucks SafeString reaching the escaper (via |escape on a |safe value)
      return rosValue(v.val);
    }
    throw Refusal(
      'RouterOS escaping refused a value of type ' + (typeof v) +
      ' (only strings, finite numbers and booleans can become a RouterOS value)'
    );
  }

  /** Bare identifiers: interface names, list names, chain names. Throws — an
   *  identifier that needs quoting is an identifier the author did not intend. */
  var IDENT = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/;
  function rosIdent(v) {
    if (typeof v !== 'string' || !IDENT.test(v)) {
      throw Refusal('rosBare refused ' + JSON.stringify(String(v)) + ': not a RouterOS identifier');
    }
    return v;
  }

  // ==========================================================================
  // Network filters — pure JS, on purpose.
  // ==========================================================================
  //
  // 'ip-address' is a server dependency and it stays on the server: passing a
  // live Address4 instance into the sandbox would hand the template a host
  // object whose '.constructor' walks straight back out of the realm. These are
  // BigInt reimplementations of the four filters the milestone asks for, and
  // they are self-contained for that reason and no other.

  function parseCidr(input, needPrefix) {
    if (typeof input !== 'string') throw Refusal('expected a string address, got ' + typeof input);
    var s = input.trim();
    var slash = s.lastIndexOf('/');
    var addr = slash === -1 ? s : s.slice(0, slash);
    var prefix = slash === -1 ? null : s.slice(slash + 1);
    var v6 = addr.indexOf(':') !== -1;
    var bits = v6 ? 128 : 32;
    var value = v6 ? parseV6(addr) : parseV4(addr);
    var len;
    if (prefix === null) {
      if (needPrefix) throw Refusal('expected a CIDR (a.b.c.d/len), got ' + JSON.stringify(s));
      len = bits;
    } else {
      if (!/^[0-9]{1,3}$/.test(prefix)) throw Refusal('invalid prefix length in ' + JSON.stringify(s));
      len = parseInt(prefix, 10);
      if (len > bits) throw Refusal('prefix length ' + len + ' is out of range for this family');
    }
    return { value: value, len: len, bits: bits, v6: v6 };
  }

  function parseV4(a) {
    var parts = a.split('.');
    if (parts.length !== 4) throw Refusal('invalid IPv4 address ' + JSON.stringify(a));
    var n = 0n;
    for (var i = 0; i < 4; i++) {
      if (!/^[0-9]{1,3}$/.test(parts[i])) throw Refusal('invalid IPv4 address ' + JSON.stringify(a));
      var o = parseInt(parts[i], 10);
      if (o > 255) throw Refusal('invalid IPv4 octet in ' + JSON.stringify(a));
      n = (n << 8n) | BigInt(o);
    }
    return n;
  }

  function parseV6(a) {
    var halves = a.split('::');
    if (halves.length > 2) throw Refusal('invalid IPv6 address ' + JSON.stringify(a));
    var head = halves[0] ? halves[0].split(':') : [];
    var tail = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : [];
    if (halves.length === 1 && head.length !== 8) throw Refusal('invalid IPv6 address ' + JSON.stringify(a));
    var missing = 8 - head.length - tail.length;
    if (missing < 0) throw Refusal('invalid IPv6 address ' + JSON.stringify(a));
    var groups = head.concat(new Array(halves.length === 2 ? missing : 0).fill('0'), tail);
    var n = 0n;
    for (var i = 0; i < groups.length; i++) {
      if (!/^[0-9A-Fa-f]{1,4}$/.test(groups[i])) throw Refusal('invalid IPv6 group in ' + JSON.stringify(a));
      n = (n << 16n) | BigInt(parseInt(groups[i], 16));
    }
    return n;
  }

  function formatV4(n) {
    return [(n >> 24n) & 255n, (n >> 16n) & 255n, (n >> 8n) & 255n, n & 255n].join('.');
  }

  function formatV6(n) {
    var g = [];
    for (var i = 7; i >= 0; i--) g.push((((n >> BigInt(i * 16)) & 0xffffn)).toString(16));
    // Longest run of zero groups collapses to '::' — canonical form (RFC 5952),
    // because two spellings of the same address would make every diff lie.
    var best = -1, bestLen = 0, cur = -1, curLen = 0;
    for (var j = 0; j < 8; j++) {
      if (g[j] === '0') { if (cur === -1) { cur = j; curLen = 1; } else { curLen++; } }
      else { if (curLen > bestLen) { best = cur; bestLen = curLen; } cur = -1; curLen = 0; }
    }
    if (curLen > bestLen) { best = cur; bestLen = curLen; }
    if (bestLen < 2) return g.join(':');
    return g.slice(0, best).join(':') + '::' + g.slice(best + bestLen).join(':');
  }

  function fmt(n, v6) { return v6 ? formatV6(n) : formatV4(n); }

  function maskOf(c) {
    var all = (1n << BigInt(c.bits)) - 1n;
    return c.len === 0 ? 0n : (all << BigInt(c.bits - c.len)) & all;
  }

  function networkOf(c) { return c.value & maskOf(c); }

  function fBroadcast(input) {
    var c = parseCidr(input, true);
    if (c.v6) throw Refusal('broadcast is meaningless for IPv6');
    var all = (1n << 32n) - 1n;
    return formatV4(networkOf(c) | (all ^ maskOf(c)));
  }

  function fNetmask(input) {
    var c = parseCidr(input, true);
    if (c.v6) throw Refusal('netmask is IPv4 only; use the prefix length for IPv6');
    return formatV4(maskOf(c));
  }

  function fNetwork(input) {
    var c = parseCidr(input, true);
    return fmt(networkOf(c), c.v6);
  }

  /**
   * cidrHost('10.0.0.0/24', 1) -> '10.0.0.1'
   * A negative index counts from the end: -1 is the last address of the block.
   * Out of range THROWS: silently wrapping around would put the gateway of one
   * site in the subnet of another.
   */
  function fCidrHost(input, index) {
    var c = parseCidr(input, true);
    if (typeof index !== 'number' || !isFinite(index) || Math.floor(index) !== index) {
      throw Refusal('cidrHost expects an integer index');
    }
    var size = 1n << BigInt(c.bits - c.len);
    var i = BigInt(index);
    if (i < 0n) i = size + i;
    if (i < 0n || i >= size) {
      throw Refusal('cidrHost index ' + index + ' is outside ' + input);
    }
    return fmt(networkOf(c) + i, c.v6);
  }

  function fPrefixLen(input) { return parseCidr(input, true).len; }

  function fHostCount(input) {
    var c = parseCidr(input, true);
    var size = 1n << BigInt(c.bits - c.len);
    // Number() is safe up to /21 in v6 terms; beyond that the count is not a
    // thing anybody puts in a config, and a wrong number would be worse.
    if (size > 9007199254740991n) throw Refusal('host count too large to represent');
    return Number(size);
  }

  // ==========================================================================
  // The loader — an in-memory map, and there is no other kind here.
  // ==========================================================================
  //
  // Partials come from the DATABASE, resolved by the parent thread before this
  // realm existed. The sandbox holds a plain object and cannot reach a
  // filesystem: '{% include "/etc/passwd" %}' and
  // '{% include "C:/Windows/win.ini" %}' both resolve to "not found", and so
  // does anything a template computes at runtime that the parent did not pin.
  var MapLoader = nunjucks.Loader.extend({
    init: function (sources) {
      this.sources = sources;
      this.async = false;
    },
    // Defeats the base class's path-relative resolution, which is the only
    // place a name could grow a directory component.
    isRelative: function () { return false; },
    resolve: function (from, to) { return to; },
    getSource: function (name) {
      if (typeof name !== 'string') return null;
      if (!hasOwn.call(this.sources, name)) return null;
      return { src: this.sources[name], path: name, noCache: false };
    }
  });

  function buildEnv(sources, options) {
    var env = new nunjucks.Environment(new MapLoader(sources), {
      autoescape: options.autoescape,
      throwOnUndefined: options.throwOnUndefined,
      trimBlocks: options.trimBlocks,
      lstripBlocks: options.lstripBlocks,
      dev: false,
      web: { async: false, useCache: false }
    });

    var SafeString = nunjucks.runtime.SafeString;
    var safe = function (s) { return new SafeString(s); };

    env.addFilter('ros', function (v) { return safe(rosValue(v)); });
    env.addFilter('rosBare', function (v) { return safe(rosIdent(v)); });
    env.addFilter('rosComment', function (v) {
      if (typeof v !== 'string') v = rosValue(v);
      return safe('"' + escapeQuotedBody(String(v)) + '"');
    });
    env.addFilter('rosList', function (v, sep) {
      if (!Array.isArray(v)) throw Refusal('rosList expects an array');
      var out = [];
      for (var i = 0; i < v.length; i++) out.push(rosIdent(v[i]));
      return safe(out.join(typeof sep === 'string' ? sep : ','));
    });

    env.addFilter('cidrHost', function (v, i) { return fCidrHost(v, i); });
    env.addFilter('netmask', fNetmask);
    env.addFilter('network', fNetwork);
    env.addFilter('broadcast', fBroadcast);
    env.addFilter('prefixLen', fPrefixLen);
    env.addFilter('hostCount', fHostCount);

    env.addGlobal('range', function (start, stop, step) {
      var a = start, b = stop, s = step;
      if (b === undefined) { b = a; a = 0; }
      if (s === undefined) s = 1;
      a = Number(a); b = Number(b); s = Number(s);
      if (!isFinite(a) || !isFinite(b) || !isFinite(s) || s === 0) {
        throw Refusal('range() needs finite bounds and a non-zero step');
      }
      var count = Math.max(0, Math.ceil((b - a) / s));
      if (count > MAX_RANGE) {
        throw Refusal(
          'range() refused to build ' + count + ' values (limit ' + MAX_RANGE +
          '): a configuration template does not loop that many times'
        );
      }
      var out = [];
      if (s > 0) { for (var i = a; i < b; i += s) out.push(i); }
      else { for (var j = a; j > b; j += s) out.push(j); }
      return out;
    });

    return env;
  }

  // ==========================================================================
  // Autoescape, rewired.
  // ==========================================================================
  //
  // Nunjucks hard-wires HTML escaping into 'lib.escape' and offers no hook. An
  // HTML escaper on a RouterOS command line is worse than none: it turns a
  // quote into '&#34;' — which does not neutralise it for RouterOS and does
  // corrupt legitimate text. Replacing the function on the module object is
  // enough because 'runtime.suppressValue' looks it up on that object at call
  // time; it is verified by the offensive test suite, not assumed.
  //
  // The consequence is the important part: EVERY '{{ ... }}' is RouterOS-escaped
  // by default and opting out takes an explicit '| safe'. Default-safe, and the
  // unsafe path is greppable.
  //
  // TWO hooks, because nunjucks has two paths:
  //   * 'lib.escape' is what the explicit '| escape' / '| e' filter calls;
  //   * 'runtime.suppressValue' is what every '{{ ... }}' calls, and the stock
  //     implementation does 'val.toString()' BEFORE escaping. Leaving that in
  //     place would mean the escaper never sees a boolean, a number or an
  //     object — only their stringification — so 'yes'/'no' would never happen
  //     and '[object Object]' would reach a router instead of being refused.
  //     Replacing it is what makes the refusal rules of rosValue actually apply
  //     to the default interpolation path.
  nunjucks.lib.escape = function (v) { return rosValue(v); };

  var SafeStringCtor = nunjucks.runtime.SafeString;
  nunjucks.runtime.suppressValue = function (val, autoescape) {
    // Matches the stock contract: null/undefined are already refused upstream
    // by ensureDefined when throwOnUndefined is on, and render as empty
    // otherwise. Changing that here would change what a template MEANS, not
    // just how it escapes.
    if (val === undefined || val === null) return '';
    if (val instanceof SafeStringCtor) return val;
    if (!autoescape) return val;
    return rosValue(val);
  };

  globalThis.__owRender = function (jobJson) {
    // Both handles are removed from the realm before a single line of the
    // template runs. They are not an escape — everything they reference is
    // realm-local — but a template that can call the renderer recursively is a
    // stack overflow somebody will find by accident.
    delete globalThis.__owJob;
    delete globalThis.__owRender;
    var job = JSON.parse(jobJson);
    var env = buildEnv(job.sources, job.options);
    var ctx = JSON.parse(job.contextJson);
    var out = env.render(job.entry, ctx);
    if (typeof out !== 'string') {
      throw Refusal('the sandbox produced a non-string result');
    }
    return out;
  };
})();
`;

// ============================================================================
// The worker bootstrap — this realm, not the sandbox's.
// ============================================================================

function post(msg: RenderWorkerMessage): void {
  parentPort?.postMessage(msg);
}

/**
 * The dynamic-import case documented at the top of the file: the rejection
 * surfaces as an uncaught exception from a microtask, after `runInContext`
 * has already returned. Reporting it and exiting is the difference between
 * "this template was refused" and "the render never came back".
 */
function installFatalHandlers(currentJobId: () => string | null): void {
  const fatal = (err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    const id = currentJobId();
    if (id) {
      post({
        type: 'result',
        id,
        ok: false,
        output: null,
        errorKind: 'template',
        errorMessage:
          'the template was refused by the sandbox: ' + message +
          ' (a template that tries to load a module tears the sandbox down; ' +
          'no module is ever loaded)',
        durationMs: 0,
      });
    } else {
      post({ type: 'fatal', kind: 'internal', message });
    }
    process.exit(0);
  };
  process.on('uncaughtException', fatal);
  process.on('unhandledRejection', fatal);
}

function classify(err: unknown): { kind: RenderWorkerErrorKind; message: string } {
  const anyErr = err as any;
  if (anyErr && anyErr.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT') {
    return { kind: 'timeout', message: 'template execution exceeded the render timeout' };
  }
  const message = err instanceof Error ? err.message : String(err);
  return { kind: 'template', message };
}

function main(): void {
  const input = workerData as RenderWorkerInput;
  let currentId: string | null = null;
  installFatalHandlers(() => currentId);

  for (const job of input.jobs) {
    currentId = job.id;
    const started = Date.now();
    try {
      // A FRESH realm per job. Two devices rendered by the same worker never
      // share a prototype, a cached template or a mutated global — one poisoned
      // template cannot reach the render of the next device.
      const context = vm.createContext(undefined, {
        codeGeneration: { strings: true, wasm: false },
      });

      // Nunjucks compiles templates with `new Function`, so string code
      // generation must stay enabled — which is exactly why the realm the
      // generated code lands in has to be empty.
      vm.runInContext(input.bundleSource, context, {
        filename: 'nunjucks-browser-bundle.js',
        timeout: input.timeoutMs,
      });
      vm.runInContext(SANDBOX_PROGRAM, context, {
        filename: 'obliwan-sandbox.js',
        timeout: input.timeoutMs,
      });

      // Only a string crosses in. `job` is re-serialised here rather than
      // assigned as an object: assigning an object would place a THIS-realm
      // object inside the sandbox, and `x.constructor.constructor` on it is the
      // escape this whole file exists to prevent.
      (context as any).__owJob = JSON.stringify(job);

      const output = vm.runInContext('__owRender(__owJob)', context, {
        filename: 'obliwan-render.js',
        timeout: input.timeoutMs,
        breakOnSigint: false,
      });

      if (typeof output !== 'string') {
        post({
          type: 'result', id: job.id, ok: false, output: null,
          errorKind: 'sandbox',
          errorMessage: 'the sandbox returned a non-string value',
          durationMs: Date.now() - started,
        });
        continue;
      }
      if (Buffer.byteLength(output, 'utf8') > input.maxOutputBytes) {
        post({
          type: 'result', id: job.id, ok: false, output: null,
          errorKind: 'output_too_large',
          errorMessage:
            'rendered output exceeds ' + input.maxOutputBytes + ' bytes',
          durationMs: Date.now() - started,
        });
        continue;
      }

      post({
        type: 'result', id: job.id, ok: true, output,
        errorKind: null, errorMessage: null,
        durationMs: Date.now() - started,
      });
    } catch (err) {
      const { kind, message } = classify(err);
      post({
        type: 'result', id: job.id, ok: false, output: null,
        errorKind: kind, errorMessage: message,
        durationMs: Date.now() - started,
      });
    }
  }

  currentId = null;
  post({ type: 'done' });
}

if (parentPort) {
  try {
    main();
  } catch (err) {
    post({
      type: 'fatal',
      kind: 'internal',
      message: err instanceof Error ? err.message : String(err),
    });
  }
}
