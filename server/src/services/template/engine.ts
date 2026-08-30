import { Worker } from 'worker_threads';
import fs from 'fs';
import path from 'path';
import { logger } from '../../utils/logger';
import type {
  RenderWorkerInput,
  RenderWorkerJob,
  RenderWorkerMessage,
  RenderWorkerErrorKind,
} from './renderWorker';

/**
 * engine.ts — the gate in front of the prison.
 *
 * `renderWorker.ts` is where a template cannot reach anything. This file is
 * where nothing reachable is ever handed to it, and where a worker that
 * misbehaves is killed rather than waited on.
 *
 * ┌─ THE FOUR THINGS THIS FILE IS RESPONSIBLE FOR ────────────────────────────┐
 * │ 1. THE CONTEXT IS JSON, AND IT IS PROVED, NOT PROMISED. `assertJsonPure`  │
 * │    walks the whole value and refuses anything that is not a JSON scalar,  │
 * │    a plain array or a plain object: no function, no accessor, no Date, no │
 * │    Buffer, no Map, no class instance, no inherited prototype, no          │
 * │    '__proto__' key. Then the value is SERIALISED and only the string      │
 * │    crosses the thread boundary. Structured cloning would have been        │
 * │    enough for most of that, and it is not what we do: a Date survives     │
 * │    structured cloning as a live Date, and a live Date inside the sandbox  │
 * │    is a host-realm constructor two property lookups from `Function`.      │
 * │ 2. THE TIMEOUT IS ENFORCED TWICE. The sandbox's own `vm` timeout          │
 * │    interrupts the script from inside; this file also runs a watchdog that │
 * │    terminates the worker if it goes quiet, because a thread that is stuck │
 * │    somewhere V8 cannot interrupt still has to stop being our problem.     │
 * │ 3. THE MEMORY CEILING IS A THREAD PROPERTY. `resourceLimits` is set at    │
 * │    spawn; a template that allocates without bound kills its own thread    │
 * │    with ERR_WORKER_OUT_OF_MEMORY and leaves the API process untouched.    │
 * │ 4. A WORKER THAT DIES STILL PRODUCES ANSWERS. Every request gets a        │
 * │    result, including the ones that were queued behind the job that killed │
 * │    the thread. A render that silently never returns is how a rollout      │
 * │    hangs at 3 a.m.                                                        │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * CAPABILITY: composing a render is `TEMPLATE_READ`; authoring or publishing
 * the body that gets rendered is `TEMPLATE_WRITE` (R6's mitigation list).
 * Enforcement lives in the controllers — which are NOT part of this milestone's
 * perimeter — but no route may expose an arbitrary template body to this
 * function without `TEMPLATE_WRITE`, because "render this string" is the same
 * privilege as "author a template".
 */

/** §6.3 R6, and the number is in the spec: five seconds, per template. */
export const TEMPLATE_RENDER_TIMEOUT_MS = 5000;

/**
 * Deliberately small. A RouterOS configuration is tens of kilobytes; anything
 * that needs 128 MB of heap to produce one is a runaway, not a template.
 * `stackSizeMb` is capped too: deep recursion through `{% include %}` is a
 * cheap way to blow a stack, and blowing a 4 MB stack in a worker is a caught
 * RangeError while blowing the main thread's is a process crash.
 */
export const TEMPLATE_WORKER_RESOURCE_LIMITS = {
  maxOldGenerationSizeMb: 64,
  maxYoungGenerationSizeMb: 16,
  codeRangeSizeMb: 16,
  stackSizeMb: 4,
} as const;

/** Guard rails on the INPUT side. A template store is operator-authored, but
 *  "operator-authored" is exactly the trust level R6 says not to grant. */
export const TEMPLATE_LIMITS = {
  maxSources: 128,
  maxSourceBytes: 512 * 1024,
  maxTotalSourceBytes: 2 * 1024 * 1024,
  maxContextBytes: 1024 * 1024,
  maxContextNodes: 20000,
  maxContextDepth: 24,
  maxStringLength: 64 * 1024,
  maxOutputBytes: 4 * 1024 * 1024,
  /** Jobs per spawned worker. Each job still gets a FRESH vm realm; this only
   *  amortises thread creation and the ~220 kB bundle parse. */
  jobsPerWorker: 16,
} as const;

export type RenderErrorKind = RenderWorkerErrorKind | 'oom' | 'worker_crash' | 'context';

export interface RenderOptions {
  /** RouterOS escaping on every `{{ }}`. Default TRUE. Turning it off is a
   *  decision about the output of a published revision and is therefore frozen
   *  with the revision (`template_revisions.render_options`). */
  autoescape?: boolean;
  /** Default TRUE, and the default matters: a missing variable that renders as
   *  an empty string produces `src-address=` — which RouterOS reads as "any". A
   *  typo in a variable name must break the render, not widen a firewall. */
  throwOnUndefined?: boolean;
  trimBlocks?: boolean;
  lstripBlocks?: boolean;
}

export interface RenderRequest {
  /** Caller correlation. Echoed back on the result; must be unique in a batch. */
  id: string;
  /** Which of `sources` is the entry point. */
  entry: string;
  /** loader name -> source. Resolved from the DATABASE by `loader.ts` before
   *  this call; the sandbox has no other way to reach a partial. */
  sources: Record<string, string>;
  context: unknown;
  options?: RenderOptions;
}

export interface RenderResult {
  id: string;
  ok: boolean;
  output: string | null;
  errorKind: RenderErrorKind | null;
  errorMessage: string | null;
  durationMs: number;
}

export class JsonPurityError extends Error {
  constructor(message: string, readonly pathText: string) {
    super(`${message} (at ${pathText})`);
    this.name = 'JsonPurityError';
  }
}

export class TemplateInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TemplateInputError';
  }
}

// ============================================================================
// 1. The context is JSON, and it is proved
// ============================================================================

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Refuses anything that is not exactly representable as JSON. Written as a
 * traversal rather than as `JSON.parse(JSON.stringify(v))` on purpose: the
 * round trip SILENTLY drops functions and undefined and silently converts a
 * Date to a string, and a silent conversion is how a caller learns nothing
 * about the live object it just tried to hand to a sandbox.
 */
export function assertJsonPure(value: unknown, label = 'context'): void {
  const seen = new Set<object>();
  let nodes = 0;

  const walk = (v: unknown, pathText: string, depth: number): void => {
    if (depth > TEMPLATE_LIMITS.maxContextDepth) {
      throw new JsonPurityError(`${label} is nested deeper than ${TEMPLATE_LIMITS.maxContextDepth}`, pathText);
    }
    if (++nodes > TEMPLATE_LIMITS.maxContextNodes) {
      throw new JsonPurityError(`${label} holds more than ${TEMPLATE_LIMITS.maxContextNodes} values`, pathText);
    }

    if (v === null) return;
    const t = typeof v;
    if (t === 'boolean') return;
    if (t === 'number') {
      if (!Number.isFinite(v as number)) {
        throw new JsonPurityError('NaN and Infinity are not JSON', pathText);
      }
      return;
    }
    if (t === 'string') {
      if ((v as string).length > TEMPLATE_LIMITS.maxStringLength) {
        throw new JsonPurityError(`string longer than ${TEMPLATE_LIMITS.maxStringLength}`, pathText);
      }
      return;
    }
    if (t === 'undefined') {
      throw new JsonPurityError('undefined is not JSON; use null', pathText);
    }
    if (t === 'function' || t === 'symbol' || t === 'bigint') {
      throw new JsonPurityError(`a ${t} cannot cross into the sandbox`, pathText);
    }

    const obj = v as object;
    if (seen.has(obj)) throw new JsonPurityError('circular reference', pathText);
    seen.add(obj);

    if (Array.isArray(obj)) {
      for (let i = 0; i < obj.length; i++) walk(obj[i], `${pathText}[${i}]`, depth + 1);
      seen.delete(obj);
      return;
    }

    // The prototype check is the load-bearing one. A `new Date()`, a Buffer, a
    // Map, a Zod object, a knex row — all of them are objects whose prototype
    // is NOT Object.prototype, and all of them carry methods whose
    // `.constructor.constructor` is this realm's `Function`.
    const proto = Object.getPrototypeOf(obj);
    if (proto !== Object.prototype && proto !== null) {
      const name = (obj as { constructor?: { name?: string } }).constructor?.name ?? 'unknown';
      throw new JsonPurityError(
        `only plain objects may cross into the sandbox, got an instance of ${name}`,
        pathText,
      );
    }
    if (Object.getOwnPropertySymbols(obj).length > 0) {
      throw new JsonPurityError('symbol-keyed properties cannot cross into the sandbox', pathText);
    }

    for (const key of Object.getOwnPropertyNames(obj)) {
      if (FORBIDDEN_KEYS.has(key)) {
        throw new JsonPurityError(`the key '${key}' is refused`, pathText);
      }
      const desc = Object.getOwnPropertyDescriptor(obj, key)!;
      if (typeof desc.get === 'function' || typeof desc.set === 'function') {
        // An accessor is code. Serialising it would run it here, and the value
        // it returns is not what a reviewer read in the variables screen.
        throw new JsonPurityError(`the property '${key}' is an accessor, not data`, pathText);
      }
      walk(desc.value, pathText === '' ? key : `${pathText}.${key}`, depth + 1);
    }
    seen.delete(obj);
  };

  walk(value, '', 0);
}

/** Validate, then serialise. The STRING is what crosses. */
export function toJsonContext(value: unknown, label = 'context'): string {
  assertJsonPure(value, label);
  const json = JSON.stringify(value ?? {});
  if (json === undefined) throw new JsonPurityError(`${label} is not serialisable`, '');
  if (Buffer.byteLength(json, 'utf8') > TEMPLATE_LIMITS.maxContextBytes) {
    throw new JsonPurityError(
      `${label} serialises to more than ${TEMPLATE_LIMITS.maxContextBytes} bytes`, '',
    );
  }
  return json;
}

function validateSources(sources: Record<string, string>, entry: string): void {
  const names = Object.keys(sources);
  if (names.length === 0) throw new TemplateInputError('no template source was provided');
  if (names.length > TEMPLATE_LIMITS.maxSources) {
    throw new TemplateInputError(`more than ${TEMPLATE_LIMITS.maxSources} template sources`);
  }
  if (!Object.prototype.hasOwnProperty.call(sources, entry)) {
    throw new TemplateInputError(`the entry template '${entry}' is not among the provided sources`);
  }
  let total = 0;
  for (const name of names) {
    const body = sources[name];
    if (typeof body !== 'string') {
      throw new TemplateInputError(`the source of '${name}' is not a string`);
    }
    const bytes = Buffer.byteLength(body, 'utf8');
    if (bytes > TEMPLATE_LIMITS.maxSourceBytes) {
      throw new TemplateInputError(`'${name}' is larger than ${TEMPLATE_LIMITS.maxSourceBytes} bytes`);
    }
    total += bytes;
  }
  if (total > TEMPLATE_LIMITS.maxTotalSourceBytes) {
    throw new TemplateInputError(
      `the template set is larger than ${TEMPLATE_LIMITS.maxTotalSourceBytes} bytes`,
    );
  }
}

// ============================================================================
// 2. Locating the two files this module needs
// ============================================================================

/**
 * The nunjucks BROWSER bundle, read once by the parent and shipped into the
 * sandbox as text.
 *
 * The browser build, not `require('nunjucks')`, and the difference is the whole
 * design: the node build is a set of CommonJS modules that can only be loaded
 * by a real module loader, i.e. in a realm that HAS `require` — the realm we
 * are trying not to give a template. The browser build is one self-contained
 * script that installs itself on whatever `globalThis` it is evaluated against,
 * so it can be evaluated inside a bare `vm` context that has no loader, no
 * `process` and no filesystem. It also means the sandbox's nunjucks physically
 * cannot contain `FileSystemLoader`'s ability to read a file, because there is
 * no `fs` in that realm to read one with.
 */
let cachedBundle: string | null = null;
function nunjucksBundleSource(): string {
  if (cachedBundle === null) {
    cachedBundle = fs.readFileSync(require.resolve('nunjucks/browser/nunjucks.js'), 'utf8');
  }
  return cachedBundle;
}

/**
 * `dist/**` after `tsc`, `src/**` under `tsx` in development. Resolved by
 * probing rather than by branching on NODE_ENV: a wrong branch here fails at
 * the first render of the day rather than at boot.
 */
let cachedWorkerPath: string | null = null;
function workerEntryPath(): string {
  if (cachedWorkerPath === null) {
    const candidates = [
      path.join(__dirname, 'renderWorker.js'),
      path.join(__dirname, 'renderWorker.ts'),
    ];
    const found = candidates.find((c) => fs.existsSync(c));
    if (!found) {
      throw new Error(`renderWorker not found; looked in ${candidates.join(', ')}`);
    }
    cachedWorkerPath = found;
  }
  return cachedWorkerPath;
}

// ============================================================================
// 3. Running a batch
// ============================================================================

function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

function fill(
  ids: string[],
  kind: RenderErrorKind,
  message: string,
): RenderResult[] {
  return ids.map((id) => ({
    id, ok: false, output: null, errorKind: kind, errorMessage: message, durationMs: 0,
  }));
}

function runWorkerBatch(jobs: RenderWorkerJob[], timeoutMs: number): Promise<RenderResult[]> {
  return new Promise((resolve) => {
    const input: RenderWorkerInput = {
      bundleSource: nunjucksBundleSource(),
      jobs,
      timeoutMs,
      maxOutputBytes: TEMPLATE_LIMITS.maxOutputBytes,
    };

    const results = new Map<string, RenderResult>();
    let settled = false;
    let worker: Worker;

    // The watchdog is ROLLING: every message resets it. A batch of sixteen
    // templates therefore never gets sixteen times the budget, and a worker
    // that stops answering mid-batch is killed one timeout after its last sign
    // of life — not after the whole batch's worth of patience.
    let watchdog: NodeJS.Timeout;
    const arm = () => {
      clearTimeout(watchdog);
      watchdog = setTimeout(() => {
        logger.error({ jobs: jobs.length }, 'template render worker went silent; terminating');
        void worker.terminate();
        finish('timeout', 'the render worker stopped responding and was terminated');
      }, timeoutMs + 1500);
    };

    const finish = (kind: RenderErrorKind, message: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(watchdog);
      const missing = jobs.filter((j) => !results.has(j.id)).map((j) => j.id);
      resolve([
        ...jobs.filter((j) => results.has(j.id)).map((j) => results.get(j.id)!),
        ...fill(missing, kind, message),
      ].sort((a, b) => jobs.findIndex((j) => j.id === a.id) - jobs.findIndex((j) => j.id === b.id)));
    };

    try {
      worker = new Worker(workerEntryPath(), {
        workerData: input,
        resourceLimits: { ...TEMPLATE_WORKER_RESOURCE_LIMITS },
        // No inherited environment: the vault key lives in this process's env
        // (`OBLIWAN_ENCRYPTION_KEY`, R8) and there is no reason for a thread
        // whose only job is string substitution to be able to read it. The
        // sandbox realm has no `process` at all, so this is the belt to that
        // pair of braces — and it is the one that also covers a bug in OUR
        // worker code rather than in the template.
        env: {},
        argv: [],
        // `execArgv` is deliberately INHERITED and not emptied: it is how the
        // TypeScript loader reaches a worker in development, and it is our own
        // configuration rather than anything a template can influence.
        stdin: false,
        stdout: true,
        stderr: true,
      });
    } catch (err) {
      resolve(fill(
        jobs.map((j) => j.id),
        'worker_crash',
        `could not start the render worker: ${err instanceof Error ? err.message : String(err)}`,
      ));
      return;
    }

    arm();

    worker.on('message', (msg: RenderWorkerMessage) => {
      arm();
      if (msg.type === 'result') {
        results.set(msg.id, {
          id: msg.id,
          ok: msg.ok,
          output: msg.output,
          errorKind: msg.errorKind,
          errorMessage: msg.errorMessage,
          durationMs: msg.durationMs,
        });
      } else if (msg.type === 'fatal') {
        finish(msg.kind, msg.message);
        void worker.terminate();
      } else if (msg.type === 'done') {
        finish('internal', 'the render worker finished without producing a result');
        void worker.terminate();
      }
    });

    worker.on('error', (err: Error & { code?: string }) => {
      const oom = err.code === 'ERR_WORKER_OUT_OF_MEMORY' ||
        /reached heap limit|out of memory/i.test(err.message);
      finish(
        oom ? 'oom' : 'worker_crash',
        oom
          ? `the template exceeded the ${TEMPLATE_WORKER_RESOURCE_LIMITS.maxOldGenerationSizeMb} MB ` +
            'memory ceiling of the render sandbox'
          : `the render worker failed: ${err.message}`,
      );
    });

    worker.on('exit', () => {
      finish('worker_crash', 'the render worker exited before producing a result');
    });
  });
}

function buildJob(req: RenderRequest): RenderWorkerJob {
  validateSources(req.sources, req.entry);
  return {
    id: req.id,
    entry: req.entry,
    sources: { ...req.sources },
    contextJson: toJsonContext(req.context, `context of '${req.id}'`),
    options: {
      autoescape: req.options?.autoescape ?? true,
      throwOnUndefined: req.options?.throwOnUndefined ?? true,
      trimBlocks: req.options?.trimBlocks ?? false,
      lstripBlocks: req.options?.lstripBlocks ?? false,
    },
  };
}

/**
 * Render a batch. Requests that fail VALIDATION (impure context, oversized
 * source) never reach a worker and come back as `context` errors; the rest are
 * split across workers and rendered.
 *
 * Never throws for a template's sake. A caller rendering a template onto 300
 * devices needs 300 answers, some of which are "this one failed and here is
 * why" — not one exception and 299 unknowns.
 */
export async function renderTemplates(
  requests: RenderRequest[],
  opts: { timeoutMs?: number } = {},
): Promise<RenderResult[]> {
  const timeoutMs = opts.timeoutMs ?? TEMPLATE_RENDER_TIMEOUT_MS;
  const rejected: RenderResult[] = [];
  const accepted: RenderWorkerJob[] = [];

  const seen = new Set<string>();
  for (const req of requests) {
    if (seen.has(req.id)) {
      rejected.push(fill([req.id], 'context', `duplicate request id '${req.id}' in one batch`)[0]);
      continue;
    }
    seen.add(req.id);
    try {
      accepted.push(buildJob(req));
    } catch (err) {
      rejected.push(
        fill([req.id], 'context', err instanceof Error ? err.message : String(err))[0],
      );
    }
  }

  const batches = chunk(accepted, TEMPLATE_LIMITS.jobsPerWorker);
  const rendered: RenderResult[] = [];
  for (const batch of batches) {
    rendered.push(...(await runWorkerBatch(batch, timeoutMs)));
  }

  const byId = new Map<string, RenderResult>();
  for (const r of [...rejected, ...rendered]) byId.set(r.id, r);
  return requests.map(
    (req) =>
      byId.get(req.id) ?? fill([req.id], 'internal', 'no result was produced for this request')[0],
  );
}

export async function renderTemplate(
  request: RenderRequest,
  opts: { timeoutMs?: number } = {},
): Promise<RenderResult> {
  const [result] = await renderTemplates([request], opts);
  return result;
}
