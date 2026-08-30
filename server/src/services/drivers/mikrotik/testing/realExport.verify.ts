/**
 * ObliWAN — the parser against a REAL RouterOS export.
 *
 * Run: npx tsx src/services/drivers/mikrotik/testing/realExport.verify.ts
 *
 * Its first run found a defect that had survived M4, five adversarial audits
 * and every hand-written fixture: `unfoldLines()` re-joined a wrapped line with
 * ONE SPACE. On `script=\` + `    ":if …` that produced `script= ":if …`, so
 * the tokenizer read `script` as EMPTY and turned the rest into phantom
 * properties. The DHCP client's bind script — the site's WAN failover — parsed
 * as nothing, and nothing anywhere said so.
 *
 * It affected every WRAPPED value, not only scripts, and the collector
 * allocates a pty, so wrapping is the normal case rather than the exception.
 */

import { parseExport } from '../parse';
import { DHCP_CLIENT_WRAPPED_SCRIPT, DHCP_CLIENT_SCRIPT_AS_SEEN } from './realExports';

let passed = 0;
let failed = 0;
function check(label: string, ok: boolean, detail?: unknown): void {
  if (ok) { passed++; console.log(`  ok   ${label}`); }
  else { failed++; console.log(`  FAIL ${label}${detail === undefined ? '' : ` — ${JSON.stringify(detail)}`}`); }
}

console.log('\n== /ip dhcp-client with a wrapped, escaped script (RouterOS 7.20.6) ==');
const p = parseExport(DHCP_CLIENT_WRAPPED_SCRIPT);
const entries = p.entries.filter((e) => e.sectionPath === '/ip/dhcp-client');

check('the preamble version is read', p.preamble.osVersion === '7.20.6', p.preamble.osVersion);
check('exactly one entry', entries.length === 1, entries.length);
check('nothing was left unparsed', p.unparsed.length === 0, p.unparsed);

const props = (entries[0]?.props ?? {}) as Record<string, string>;

check('interface', props.interface === 'ether1-WAN1', props.interface);
check('add-default-route', props['add-default-route'] === 'no', props['add-default-route']);
check('use-peer-dns', props['use-peer-dns'] === 'no', props['use-peer-dns']);
check('comment survives the wrap', props.comment === 'WAN1 DHCP', props.comment);

// THE ONE THAT MATTERED.
check('the script is byte-identical to the web UI', props.script === DHCP_CLIENT_SCRIPT_AS_SEEN,
  { got: props.script });
check('`\n` became real newlines', (props.script ?? '').split('\n').length === 4);
check('`\$` became a literal $', (props.script ?? '').includes('$bound=1'));
check('`\\"` became a literal quote', (props.script ?? '').includes('comment="NW-WAN1"'));

// The phantom properties the old join produced. Named explicitly so a
// regression is recognised rather than merely counted.
const phantom = Object.keys(props).filter((k) => k.includes('$bound') || k.startsWith('":if'));
check('no phantom property was invented', phantom.length === 0, phantom);
check('exactly the six real properties', Object.keys(props).length === 6, Object.keys(props));

console.log(`\n${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exitCode = 1;
