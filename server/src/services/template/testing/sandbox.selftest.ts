/**
 * Offensive self-test for the template sandbox — risk R6.
 *
 * WHY THIS FILE EXISTS AND MUST NOT BE DELETED
 *
 * The server that evaluates templates is the one holding the administration
 * credentials of every device of every tenant. An escape here is not a local
 * privilege escalation, it is handing over every customer's network at once.
 *
 * The sandbox was built with four layers (empty vm realm, vm timeout,
 * worker_threads + resourceLimits + empty env, JSON-only wire). Layers are easy
 * to weaken by accident — "let me just pass the device object straight through",
 * "structuredClone is faster than JSON" — and none of those edits look dangerous
 * in review. This file is what turns them into a failing test.
 *
 *   npx tsx src/services/template/testing/sandbox.selftest.ts
 *
 * Exits non-zero on the first escape. Add a case whenever a new way in is found.
 */
import { renderTemplate, assertJsonPure, TEMPLATE_RENDER_TIMEOUT_MS } from '../engine';

let pass = 0;
const failures: string[] = [];

function ok(name: string, condition: boolean, detail = ''): void {
  if (condition) { pass++; return; }
  failures.push(`${name}${detail ? ' — ' + detail : ''}`);
}

/** Render one template with no context and return the result. */
async function tryRender(body: string, context: unknown = {}, timeoutMs?: number) {
  return renderTemplate(
    { id: 'probe', entry: 'main', sources: { main: body }, context },
    timeoutMs === undefined ? {} : { timeoutMs },
  );
}

/** An escape attempt must NOT produce output containing the marker. */
async function mustNotLeak(name: string, body: string, marker: RegExp): Promise<void> {
  const r = await tryRender(body);
  const leaked = r.ok && r.output !== null && marker.test(r.output);
  ok(name, !leaked, leaked ? `LEAKED: ${String(r.output).slice(0, 200)}` : '');
}

async function main(): Promise<void> {
  // ---------------------------------------------------------------------
  // 1. The classic Nunjucks escape: climb to Function through a constructor.
  // ---------------------------------------------------------------------
  await mustNotLeak(
    'constructor.constructor -> process',
    `{{ "".constructor.constructor("return process.env")() }}`,
    /[A-Z_]+=|DATABASE_URL|SESSION_SECRET|OBLIWAN/,
  );
  await mustNotLeak(
    'range.constructor',
    `{{ range.constructor("return process")() }}`,
    /object process|pid|versions/,
  );
  await mustNotLeak(
    'cycler/joiner constructor climb',
    `{{ cycler.constructor.constructor("return globalThis")() }}`,
    /process|require|global/,
  );

  // ---------------------------------------------------------------------
  // 2. The realm must simply not contain the host's tools.
  // ---------------------------------------------------------------------
  for (const g of ['process', 'require', 'fetch', 'Buffer', 'setTimeout', 'console',
                   'SharedArrayBuffer', 'Atomics', 'WebAssembly', 'globalThis.process']) {
    const r = await tryRender(`{{ ${g} }}`);
    const present = r.ok && r.output !== null && r.output.trim() !== '' &&
                    !/undefined/i.test(r.output);
    ok(`global absent: ${g}`, !present, present ? `got: ${String(r.output).slice(0, 120)}` : '');
  }

  // ---------------------------------------------------------------------
  // 3. The vault key lives in the environment. It must not be reachable.
  // ---------------------------------------------------------------------
  process.env.__SANDBOX_CANARY__ = 'CANARY-must-never-appear';
  await mustNotLeak('process.env canary', `{{ process.env.__SANDBOX_CANARY__ }}`, /CANARY-must-never-appear/);
  await mustNotLeak(
    'env canary via constructor climb',
    `{{ "".constructor.constructor("return process.env.__SANDBOX_CANARY__")() }}`,
    /CANARY-must-never-appear/,
  );

  // ---------------------------------------------------------------------
  // 4. Denial of service: an infinite loop must be interrupted, and the call
  //    must return rather than hang the API thread.
  // ---------------------------------------------------------------------
  {
    const started = Date.now();
    const r = await tryRender(`{% for i in range(0, 100000000) %}{{ i }}{% endfor %}`, {}, 1500);
    const elapsed = Date.now() - started;
    ok('infinite loop is interrupted', !r.ok, r.ok ? 'render returned ok' : '');
    ok('interruption is bounded in time', elapsed < 20000, `took ${elapsed} ms`);
  }

  // ---------------------------------------------------------------------
  // 5. The filesystem must be unreachable, including through include.
  // ---------------------------------------------------------------------
  {
    const r = await tryRender(`{% include "/etc/passwd" %}`);
    ok('include of an absolute path fails', !r.ok || !/root:/.test(r.output ?? ''));
  }
  await mustNotLeak(
    'fs through a constructor climb',
    `{{ "".constructor.constructor("return require('fs').readFileSync('/etc/hostname','utf8')")() }}`,
    /\w/,
  );

  // ---------------------------------------------------------------------
  // 6. The JSON-only wire. A live object must never cross.
  // ---------------------------------------------------------------------
  {
    let threw = false;
    try { assertJsonPure({ fn: () => 'live' }); } catch { threw = true; }
    ok('assertJsonPure refuses a function', threw);
  }
  {
    let threw = false;
    try { assertJsonPure({ when: new Date() }); } catch { threw = true; }
    ok('assertJsonPure refuses a Date (host-realm constructor)', threw);
  }
  {
    let threw = false;
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    try { assertJsonPure(circular); } catch { threw = true; }
    ok('assertJsonPure refuses a cycle', threw);
  }
  {
    let threw = false;
    try { assertJsonPure(JSON.parse('{"__proto__": {"polluted": true}}')); } catch { threw = true; }
    ok('assertJsonPure refuses __proto__', threw);
  }
  {
    // A live object reaching the sandbox would give the template a host
    // constructor two lookups from Function.
    const r = await tryRender(`{{ dev.constructor.constructor("return process")() }}`, { dev: { name: 'x' } });
    ok('a context object exposes no host constructor',
       !r.ok || !/object process|pid/.test(r.output ?? ''));
  }

  // ---------------------------------------------------------------------
  // 7. RouterOS escaping is a security boundary, not cosmetics.
  //    A variable must not be able to terminate the command and start another.
  // ---------------------------------------------------------------------
  {
    const r = await tryRender(
      `/ip firewall address-list add list={{ name }} address=10.0.0.1`,
      { name: 'x;/system reboot;' },
    );
    // A `;` inside a RouterOS quoted string is one token and terminates nothing,
    // so the check is NOT "does the output contain a semicolon" — the escaper is
    // supposed to keep the characters and neutralise them. What must not exist is
    // a semicolon OUTSIDE the quotes. Strip every quoted segment (honouring
    // backslash escapes) and look at what is left.
    const outsideQuotes = (r.output ?? '').replace(/"(?:\\.|[^"\\])*"/g, '""');
    const injected = r.ok && /;/.test(outsideQuotes);
    ok('a semicolon in a value cannot inject a second command', !injected,
       injected ? `unquoted ";" in: ${r.output}` : '');
    ok('and the dangerous value is actually quoted, not silently dropped',
       r.ok && /list="x;\/system reboot;"/.test(r.output ?? ''),
       `output: ${r.output}`);
  }
  {
    const r = await tryRender(`/ip firewall filter add chain=input {{ opt }}`, { opt: '!src-address=1.2.3.4' });
    // `!` inverts a firewall match: emitting it bare would silently reverse a rule.
    const bare = r.ok && r.output !== null && /\s!src-address/.test(r.output);
    ok('a bare "!" cannot reach the command line', !bare, bare ? `output: ${r.output}` : '');
  }
  {
    const r = await tryRender(`address={{ ip }}/24`, { ip: '10.0.0.1' });
    ok('a safe value is still emitted verbatim', r.ok && (r.output ?? '').includes('10.0.0.1/24'),
       `output: ${r.output}`);
  }

  // ---------------------------------------------------------------------
  // 8. The default timeout is the one the milestone specified.
  // ---------------------------------------------------------------------
  ok('default timeout is 5 s', TEMPLATE_RENDER_TIMEOUT_MS === 5000,
     `got ${TEMPLATE_RENDER_TIMEOUT_MS}`);

  delete process.env.__SANDBOX_CANARY__;

  console.log(`\n${pass} passed, ${failures.length} failed`);
  if (failures.length > 0) {
    console.error('\nESCAPES / REGRESSIONS:');
    for (const f of failures) console.error('  - ' + f);
    process.exit(1);
  }
  console.log('Sandbox holds.');
}

void main().catch((err) => { console.error(err); process.exit(1); });
