// ============================================================================
// ObliWAN — golden files for the intent compiler (M11 — K4)
// ============================================================================
//
// ┌─ WHAT A GOLDEN FILE HERE IS, AND WHAT IT IS NOT ──────────────────────────┐
// │ IS:     a byte-exact freeze of what THIS compiler renders for one family  │
// │         from one fixed intent. One character of difference in a rule, in  │
// │         an interface name, in the order of two lines, or in the NCM hash  │
// │         breaks the build. That is the whole point: a rendering change     │
// │         must be a decision somebody made, reviewed in a diff, and not a   │
// │         side effect noticed on a customer's router three weeks later.     │
// │                                                                           │
// │ IS NOT: evidence that a Vigor, a Zyxel, a SonicWall or even a MikroTik    │
// │         accepts any of it. No such appliance exists here (§8.3). The      │
// │         golden files prove determinism and intentionality of change, and  │
// │         nothing at all about vendor syntax.                               │
// └───────────────────────────────────────────────────────────────────────────┘
//
// Regenerate deliberately:   npx tsx src/services/intent/testing/goldenFiles.ts --update
// Check (what CI runs):      npx tsx src/services/intent/testing/m11-intent.verify.ts

import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import type { DeviceFamily } from '@obliwan/shared';
import { compileIntent } from '../compiler.service';
import { renderableFamilies } from '../brandProfiles';
import { GOLDEN_TARGET, referenceSiteIntent } from './fixtures';

export const GOLDEN_DIR = join(__dirname, '..', 'golden');

export function goldenPath(family: DeviceFamily): string {
  return join(GOLDEN_DIR, `${family}.golden`);
}

/**
 * The frozen bytes: the NCM hash, the artefact digest and the artefact itself.
 *
 * The two hashes are in the file rather than in a side manifest so that a
 * reviewer reading the diff sees, in one place, whether the change touched the
 * MODEL (ncm-hash moved, so the plan and the drift comparison move too) or only
 * the RENDERING (artifact-sha256 moved alone).
 */
export function buildGolden(family: DeviceFamily): string {
  const compilation = compileIntent(referenceSiteIntent(), { ...GOLDEN_TARGET, family });
  return [
    `# ObliWAN golden file — ${family}`,
    `# intent: ${referenceSiteIntent().slug} (schema v${compilation.schemaVersion}), compiler v${compilation.compilerVersion}`,
    `# ncm-hash: ${compilation.ncmHash}`,
    `# artifact-sha256: ${compilation.artifact.sha256}`,
    `# artifact-format: ${compilation.artifact.format}`,
    '# ---------------------------------------------------------------------------',
    '',
    compilation.artifact.body,
  ].join('\n');
}

export interface GoldenMismatch {
  family: DeviceFamily;
  reason: 'missing' | 'differs';
  /** First differing line, 1-based, for a diff a human can jump to. */
  line: number | null;
  expected: string | null;
  actual: string | null;
}

/** Compare every renderable family against its frozen file. */
export function checkGoldenFiles(): GoldenMismatch[] {
  const mismatches: GoldenMismatch[] = [];
  for (const family of renderableFamilies()) {
    const path = goldenPath(family);
    const actual = buildGolden(family);
    if (!existsSync(path)) {
      mismatches.push({ family, reason: 'missing', line: null, expected: null, actual: null });
      continue;
    }
    const expected = readFileSync(path, 'utf8');
    if (expected === actual) continue;
    const a = actual.split('\n');
    const e = expected.split('\n');
    let line = 0;
    while (line < a.length && line < e.length && a[line] === e[line]) line += 1;
    mismatches.push({
      family,
      reason: 'differs',
      line: line + 1,
      expected: e[line] ?? '(end of file)',
      actual: a[line] ?? '(end of file)',
    });
  }
  return mismatches;
}

/** Rewrite every golden file. Never called by the verification run — a test
 *  that repairs its own oracle tests nothing. */
export function writeGoldenFiles(): DeviceFamily[] {
  if (!existsSync(GOLDEN_DIR)) mkdirSync(GOLDEN_DIR, { recursive: true });
  const written: DeviceFamily[] = [];
  for (const family of renderableFamilies()) {
    writeFileSync(goldenPath(family), buildGolden(family), 'utf8');
    written.push(family);
  }
  return written;
}

/** Golden files whose family no longer renders — a stale oracle nobody reads. */
export function orphanGoldenFiles(): string[] {
  if (!existsSync(GOLDEN_DIR)) return [];
  const expected = new Set(renderableFamilies().map((f) => `${f}.golden`));
  return readdirSync(GOLDEN_DIR).filter((name) => name.endsWith('.golden') && !expected.has(name));
}

if (require.main === module) {
  if (process.argv.includes('--update')) {
    const written = writeGoldenFiles();
    process.stdout.write(`wrote ${written.length} golden file(s): ${written.join(', ')}\n`);
    const orphans = orphanGoldenFiles();
    if (orphans.length > 0) {
      process.stdout.write(`WARNING — orphan golden files: ${orphans.join(', ')}\n`);
    }
  } else {
    const mismatches = checkGoldenFiles();
    if (mismatches.length === 0) {
      process.stdout.write('golden files match\n');
    } else {
      for (const m of mismatches) {
        process.stdout.write(
          `${m.family}: ${m.reason}${m.line ? ` at line ${m.line}\n  expected: ${m.expected}\n  actual:   ${m.actual}` : ''}\n`,
        );
      }
      process.exitCode = 1;
    }
  }
}
