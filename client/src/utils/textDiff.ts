// ObliWAN client — the line diff engine.
//
// §8.1 of the spec: **three diffs, one engine, one component**. The three are
// (1) a configuration snapshot against another, (2) the textual patch that
// accompanies a drift finding, and (3) an export bundle against the current
// instance — which is the import plan and arrives later. So nothing in this
// file, and nothing in `components/common/DiffViewer`, may know what an NCM is.
// The engine's whole vocabulary is: two arrays of lines, or one unified patch.
//
// ── WHY A HAND-WRITTEN MYERS AND NOT A LIBRARY ──────────────────────────────
// The client already ships 1.9 MB of bundle. `diff` / `jsdiff` is ~30 kB raw
// for one function we use one shape of, and the greedy Myers algorithm is
// ~60 lines. The version below is the standard O(ND) forward pass with a
// bounded `d`: past the bound it does NOT silently produce a bad diff, it
// reports `degraded: true` and falls back to "everything removed, everything
// added", which the viewer labels. A diff that quietly mis-aligns two configs
// is worse than no diff at all — the operator would read a change that is not
// there, which is the exact failure mode R3 is about.

export type DiffLineType = 'context' | 'add' | 'del';

export interface DiffLine {
  type: DiffLineType;
  /** 1-based line number on the left side, or null for an addition. */
  leftNo: number | null;
  /** 1-based line number on the right side, or null for a deletion. */
  rightNo: number | null;
  text: string;
}

export interface DiffHunk {
  leftStart: number;
  rightStart: number;
  lines: DiffLine[];
  /** Unchanged lines skipped BEFORE this hunk. 0 for the first hunk when the
   *  file starts with a change. */
  skippedBefore: number;
}

export interface DiffResult {
  hunks: DiffHunk[];
  added: number;
  removed: number;
  /** The engine hit its work bound and fell back to a wholesale replacement.
   *  Surfaced in the UI, never swallowed. */
  degraded: boolean;
  /** Output was cut at `maxLines`. Also surfaced. */
  truncated: boolean;
  /** True when the two sides are byte-identical. Distinct from "no hunks
   *  because everything was filtered", which is not the same statement. */
  identical: boolean;
}

/** Maximum edit distance the greedy pass will explore before degrading.
 *  A RouterOS `/export` is 300–3000 lines; two consecutive snapshots of the
 *  same device differ by a handful of lines, so `d` stays tiny in practice.
 *  The bound only fires on genuinely unrelated inputs, where a line-by-line
 *  alignment would be meaningless anyway. */
const MAX_EDIT_DISTANCE = 3000;

/** Hard cap on rendered lines. A 20 000-line diff is not read, it is scrolled
 *  past; the cap keeps the DOM from being the reason the page dies. */
export const DEFAULT_MAX_LINES = 4000;

export function splitLines(text: string): string[] {
  if (text === '') return [];
  // Normalise CRLF so a Windows-collected export does not diff as 100 % changed
  // against a Unix-collected one. That is a transport artefact, not a change —
  // exactly the class of noise the normalisation study exists to kill.
  return text.replace(/\r\n?/g, '\n').replace(/\n$/, '').split('\n');
}

interface Edit {
  type: DiffLineType;
  left: number;  // index into a[], -1 for an addition
  right: number; // index into b[], -1 for a deletion
}

/**
 * Greedy forward Myers with a work bound, plus the usual common
 * prefix/suffix trim which does most of the work on real configs.
 */
function myers(a: readonly string[], b: readonly string[]): { edits: Edit[]; degraded: boolean } {
  const edits: Edit[] = [];

  let start = 0;
  const nA = a.length;
  const nB = b.length;
  while (start < nA && start < nB && a[start] === b[start]) start++;
  let endA = nA;
  let endB = nB;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) { endA--; endB--; }

  for (let i = 0; i < start; i++) edits.push({ type: 'context', left: i, right: i });

  const midA = a.slice(start, endA);
  const midB = b.slice(start, endB);
  const n = midA.length;
  const m = midB.length;

  const pushTail = (): void => {
    for (let i = endA; i < nA; i++) edits.push({ type: 'context', left: i, right: i - nA + nB });
  };

  if (n === 0 || m === 0) {
    for (let i = 0; i < n; i++) edits.push({ type: 'del', left: start + i, right: -1 });
    for (let j = 0; j < m; j++) edits.push({ type: 'add', left: -1, right: start + j });
    pushTail();
    return { edits, degraded: false };
  }

  const max = Math.min(n + m, MAX_EDIT_DISTANCE);
  const offset = max;
  const v = new Int32Array(2 * max + 1);
  const trace: Int32Array[] = [];
  let found = -1;

  outer:
  for (let d = 0; d <= max; d++) {
    trace.push(v.slice());
    for (let k = -d; k <= d; k += 2) {
      let x: number;
      if (k === -d || (k !== d && v[offset + k - 1] < v[offset + k + 1])) {
        x = v[offset + k + 1];
      } else {
        x = v[offset + k - 1] + 1;
      }
      let y = x - k;
      while (x < n && y < m && midA[x] === midB[y]) { x++; y++; }
      v[offset + k] = x;
      if (x >= n && y >= m) { found = d; break outer; }
    }
  }

  if (found < 0) {
    // Bounded out. Say so rather than pretend.
    for (let i = 0; i < n; i++) edits.push({ type: 'del', left: start + i, right: -1 });
    for (let j = 0; j < m; j++) edits.push({ type: 'add', left: -1, right: start + j });
    pushTail();
    return { edits, degraded: true };
  }

  // Backtrack.
  const mid: Edit[] = [];
  let x = n;
  let y = m;
  for (let d = found; d > 0; d--) {
    const vPrev = trace[d];
    const k = x - y;
    let prevK: number;
    if (k === -d || (k !== d && vPrev[offset + k - 1] < vPrev[offset + k + 1])) {
      prevK = k + 1;
    } else {
      prevK = k - 1;
    }
    const prevX = vPrev[offset + prevK];
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) {
      x--; y--;
      mid.push({ type: 'context', left: start + x, right: start + y });
    }
    if (prevK === k + 1) {
      y--;
      mid.push({ type: 'add', left: -1, right: start + y });
    } else {
      x--;
      mid.push({ type: 'del', left: start + x, right: -1 });
    }
  }
  while (x > 0 && y > 0) {
    x--; y--;
    mid.push({ type: 'context', left: start + x, right: start + y });
  }
  mid.reverse();
  for (const e of mid) edits.push(e);
  pushTail();
  return { edits, degraded: false };
}

export interface DiffOptions {
  /** Unchanged lines kept around each change. */
  context?: number;
  maxLines?: number;
  /** Applied to BOTH sides before comparison. Used by the viewer's
   *  "ignore whitespace" toggle and by nothing else — the engine has no
   *  opinion on what a meaningless difference is; that is the normalisation
   *  rules' job, server-side. */
  transform?: (line: string) => string;
}

export function diffLines(
  leftText: string,
  rightText: string,
  options: DiffOptions = {},
): DiffResult {
  const context = options.context ?? 3;
  const maxLines = options.maxLines ?? DEFAULT_MAX_LINES;
  const rawLeft = splitLines(leftText);
  const rawRight = splitLines(rightText);
  const cmpLeft = options.transform ? rawLeft.map(options.transform) : rawLeft;
  const cmpRight = options.transform ? rawRight.map(options.transform) : rawRight;

  const { edits, degraded } = myers(cmpLeft, cmpRight);

  let added = 0;
  let removed = 0;
  for (const e of edits) {
    if (e.type === 'add') added++;
    else if (e.type === 'del') removed++;
  }
  if (added === 0 && removed === 0) {
    return { hunks: [], added: 0, removed: 0, degraded, truncated: false, identical: true };
  }

  // Which edits to keep: every change, plus `context` around it.
  const keep = new Uint8Array(edits.length);
  for (let i = 0; i < edits.length; i++) {
    if (edits[i].type === 'context') continue;
    for (let j = Math.max(0, i - context); j <= Math.min(edits.length - 1, i + context); j++) {
      keep[j] = 1;
    }
  }

  const hunks: DiffHunk[] = [];
  let current: DiffHunk | null = null;
  let skipped = 0;
  let emitted = 0;
  let truncated = false;

  for (let i = 0; i < edits.length; i++) {
    if (!keep[i]) {
      skipped++;
      current = null;
      continue;
    }
    if (emitted >= maxLines) { truncated = true; break; }
    const e = edits[i];
    const line: DiffLine = {
      type: e.type,
      leftNo: e.left >= 0 ? e.left + 1 : null,
      rightNo: e.right >= 0 ? e.right + 1 : null,
      text: e.type === 'add' ? (rawRight[e.right] ?? '') : (rawLeft[e.left] ?? ''),
    };
    if (!current) {
      current = {
        leftStart: line.leftNo ?? 0,
        rightStart: line.rightNo ?? 0,
        lines: [],
        skippedBefore: skipped,
      };
      hunks.push(current);
      skipped = 0;
    }
    current.lines.push(line);
    emitted++;
  }

  return { hunks, added, removed, degraded, truncated, identical: false };
}

/**
 * Renders a server-supplied unified patch (`drift_findings.text_patch`) with the
 * same `DiffResult` shape, so the viewer has ONE render path.
 *
 * Deliberately tolerant: the engine that produces `text_patch` is another
 * agent's, and a fragment that carries no `@@` header at all — a bare
 * `-old` / `+new` pair, which is the most useful form for a two-line field
 * change — is a perfectly reasonable thing for it to emit. Rather than reject
 * it, that case is rendered as a single hunk with no line numbers, which is
 * honest: we do not know where in the file it sits.
 */
export function parseUnifiedPatch(patch: string, maxLines = DEFAULT_MAX_LINES): DiffResult {
  const lines = splitLines(patch);
  const hunks: DiffHunk[] = [];
  let current: DiffHunk | null = null;
  let leftNo = 0;
  let rightNo = 0;
  let added = 0;
  let removed = 0;
  let emitted = 0;
  let truncated = false;
  let sawHeader = false;

  for (const raw of lines) {
    if (emitted >= maxLines) { truncated = true; break; }
    if (raw.startsWith('@@')) {
      sawHeader = true;
      const m = /^@@\s+-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@/.exec(raw);
      leftNo = m ? Number(m[1]) : 0;
      rightNo = m ? Number(m[2]) : 0;
      current = { leftStart: leftNo, rightStart: rightNo, lines: [], skippedBefore: 0 };
      hunks.push(current);
      continue;
    }
    // File headers of a full unified diff carry no content.
    if (raw.startsWith('--- ') || raw.startsWith('+++ ') || raw.startsWith('diff ')) continue;
    if (raw.startsWith('\\')) continue;   // "\ No newline at end of file"

    if (!current) {
      current = { leftStart: 0, rightStart: 0, lines: [], skippedBefore: 0 };
      hunks.push(current);
    }
    const marker = raw.charAt(0);
    const text = raw.length > 0 ? raw.slice(1) : '';
    if (marker === '+') {
      current.lines.push({ type: 'add', leftNo: null, rightNo: sawHeader ? rightNo++ : null, text });
      added++;
    } else if (marker === '-') {
      current.lines.push({ type: 'del', leftNo: sawHeader ? leftNo++ : null, rightNo: null, text });
      removed++;
    } else {
      current.lines.push({
        type: 'context',
        leftNo: sawHeader ? leftNo++ : null,
        rightNo: sawHeader ? rightNo++ : null,
        text: marker === ' ' ? text : raw,
      });
    }
    emitted++;
  }

  return {
    hunks: hunks.filter((h) => h.lines.length > 0),
    added,
    removed,
    degraded: false,
    truncated,
    identical: added === 0 && removed === 0,
  };
}
