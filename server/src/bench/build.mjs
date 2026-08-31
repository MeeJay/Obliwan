/**
 * ObliWAN — build the bench tool as a single Windows executable (M15).
 *
 *   node src/bench/build.mjs
 *
 * ┌─ WHY SEA AND NOT `pkg` ──────────────────────────────────────────────────┐
 * │ Node 24 ships Single Executable Applications in core. `pkg` is archived   │
 * │ and pins its own Node build, which would mean the bench tool ran a        │
 * │ different runtime from the server it shares driver code with — and that   │
 * │ divergence is the exact risk this tool was written in TypeScript to       │
 * │ avoid. One language, one runtime, one renderer.                           │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE SIGNING ORDER IS LOAD-BEARING ──────────────────────────────────────┐
 * │ This script stops at the unsigned `.exe`. The rest belongs in             │
 * │ `000-RegularUpdate.bat` (gitignored — it hard-codes the internal build    │
 * │ host), and the ORDER is the part that matters, copied from Obliview's     │
 * │ `:BUILD_AGENT_WIN`:                                                       │
 * │                                                                          │
 * │   1. node src/bench/build.mjs                  -> dist/obliwan-bench.exe  │
 * │   2. Sign.ps1 -Targets 'dist\obliwan-bench.exe'                           │
 * │   3. wix build ...                             -> dist/obliwan-bench.msi  │
 * │   4. Sign.ps1 -Targets 'dist\obliwan-bench.msi'                           │
 * │                                                                          │
 * │ The exe is signed BEFORE the MSI is built so the binary embedded in the   │
 * │ installer is itself signed; the MSI is then signed separately.            │
 * │                                                                          │
 * │ ONE DEVIATION FROM OBLIVIEW, DELIBERATE: there, a failed signature is     │
 * │ logged and the pipeline continues. Here it must ABORT. This binary writes │
 * │ administrator accounts onto brand-new routers; an unsigned copy landing   │
 * │ on a preparation workstation is precisely what the signature exists to    │
 * │ prevent, and "Sign:ECHEC" in a summary nobody reads is not a control.     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The signing identity is a Certum SimplySign CLOUD certificate unlocked by a
 * TOTP — there is no `.pfx` anywhere, and `D:\Sign\.env` (outside every repo)
 * holds the OTP URI. Nothing in this repository can sign anything, which is the
 * intended property.
 */

import { build } from 'esbuild';
import { execFileSync } from 'child_process';
import { mkdirSync, copyFileSync, writeFileSync, rmSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const here = dirname(fileURLToPath(import.meta.url));
const serverRoot = join(here, '..', '..');
const dist = join(serverRoot, 'dist-bench');
const bundle = join(dist, 'bench.cjs');
const blob = join(dist, 'bench.blob');
const exe = join(dist, 'obliwan-bench.exe');

// Read from `src/bench/VERSION`, the same convention Obliview and Obliance use
// for their agents. A file rather than a field in package.json because the
// bench tool ships on its OWN cadence: it follows the CLI dialects it speaks,
// not the server's release train. The day a Vigor transcript corrects
// `SSH_DIALECTS`, this tool needs a release and the server does not.
const version = readFileSync(join(here, 'VERSION'), 'utf8').trim();
console.log(`obliwan-bench v${version}`);

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

console.log('[1/4] bundling…');
await build({
  entryPoints: [join(here, 'cli.ts')],
  bundle: true,
  platform: 'node',
  target: 'node24',
  format: 'cjs',
  outfile: bundle,
  // The drivers reach for `ssh2` and friends at run time. Bundling them is the
  // point: a preparation workstation has no npm install and no network to the
  // registry.
  external: [],
  plugins: [
    {
      // ┌─ THE DATABASE IS REPLACED BY A MODULE THAT THROWS ─────────────────┐
      // │ The bench tool must not carry a database, and the import graph      │
      // │ disagreed: `registry` -> `draytek.driver` -> `cwmpInventory` ->     │
      // │ `cwmp/inventory.service` -> `cwmp/paramMap.service` -> `db`, which  │
      // │ drags in knex and its nine SQL drivers. The build died on           │
      // │ `oracledb`, which is how the coupling was found at all.             │
      // │                                                                    │
      // │ That path is REAL on a server — a Vigor's inventory can come from   │
      // │ its stored TR-069 parameters — and MEANINGLESS on a bench, where    │
      // │ the router has never informed an ACS. So it is not excluded, it is  │
      // │ STUBBED: reaching it raises a sentence naming the tool and the      │
      // │ path, instead of a `Cannot find module 'pg'` at a customer site.    │
      // │                                                                    │
      // │ Marking it `external` would have been one word shorter and would    │
      // │ have failed silently the first time somebody wired a query into a   │
      // │ shared helper. A stub that throws is the version that stays true.   │
      // └────────────────────────────────────────────────────────────────────┘
      name: 'no-database-on-a-bench',
      setup(b) {
        b.onResolve({ filter: /(^|\/)db(\/index)?$/ }, (args) => {
          if (!args.importer.includes(`${'src'}`)) return null;
          return { path: 'obliwan-bench-no-db', namespace: 'stub' };
        });
        b.onLoad({ filter: /.*/, namespace: 'stub' }, () => ({
          // Inert on IMPORT, loud on USE. The first version threw during the
          // CJS/ESM interop shim, which probes `__esModule`/`default` on every
          // module it wraps — so the tool died at startup instead of at the
          // query it was meant to catch. The interop keys are answered; every
          // other access refuses.
          contents: `
            const refuse = () => {
              throw new Error(
                'The ObliWAN bench tool has no database. Something reached a query path — most ' +
                'likely the CWMP inventory fallback, which is meaningless for a router that has ' +
                'never informed an ACS. Read the identity over the device transport instead.'
              );
            };
            const INTEROP = new Set(['__esModule', 'default', 'then', 'prototype', 'name', 'length']);
            const stub = new Proxy(function () { refuse(); }, {
              get(target, prop) {
                if (typeof prop === 'symbol') return Reflect.get(target, prop);
                if (prop === '__esModule') return false;
                if (INTEROP.has(prop)) return undefined;
                refuse();
              },
              apply: refuse,
            });
            module.exports = stub;
          `,
          loader: 'js',
        }));
      },
    },
  ],
  // Not minified. A tool that writes administrator accounts should stay
  // readable to whoever has to audit the binary they were handed.
  minify: false,
  sourcemap: false,
  logLevel: 'info',
});

console.log('[2/4] sea-config…');
const seaConfig = join(dist, 'sea-config.json');
writeFileSync(seaConfig, JSON.stringify({
  main: bundle,
  output: blob,
  disableExperimentalSEAWarning: true,
  // No snapshot: it forbids `require()` at run time, and the drivers resolve
  // transports dynamically.
  useSnapshot: false,
  useCodeCache: true,
}, null, 2));

execFileSync(process.execPath, ['--experimental-sea-config', seaConfig], { stdio: 'inherit' });

console.log('[3/4] copying the node runtime…');
copyFileSync(process.execPath, exe);

console.log('[4/4] injecting…');
// `postject` is invoked through npx so the build host needs no global install.
execFileSync('npx', [
  '--yes', 'postject', exe, 'NODE_SEA_BLOB', blob,
  '--sentinel-fuse', 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2',
], { stdio: 'inherit', shell: process.platform === 'win32' });

// The MSI manifest carries `BENCH_VERSION_PLACEHOLDER`. Substituting it here
// keeps the version in ONE file instead of two that drift apart — the same
// trick Obliview uses for `AGENT_VERSION_PLACEHOLDER`.
const wxsOut = join(dist, 'product.wxs');
writeFileSync(
  wxsOut,
  readFileSync(join(here, 'installer', 'product.wxs'), 'utf8')
    .replace('BENCH_VERSION_PLACEHOLDER', version),
);

console.log(`\n  built: ${exe}  (v${version})`);
console.log(`  wxs:   ${wxsOut}`);
console.log('  NOT SIGNED. Sign it before building the MSI — see the box at the top.\n');
