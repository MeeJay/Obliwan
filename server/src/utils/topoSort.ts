/**
 * Topological sort of a parent-referencing list, with REAL cycle detection.
 *
 * VERIF-SECFIX-AUTRES #8 — the previous implementation lived inline in
 * `importExport.controller.ts` under the comment "Cycles are silently ignored".
 * That comment was false in the way that costs the most: cycles were neither
 * ignored nor reported, they were *ordered arbitrarily*. The `visited` set only
 * stopped the recursion, so every member of a cycle was still emitted and later
 * processed. `reparentGroupClosure` then received a `parentId` taken from the
 * subtree of the group it was reparenting, the `DELETE` could not cut the
 * `(g, g, 0)` row (its ancestor is inside `descIds`), and the `INSERT … SELECT`
 * reproduced the pair `(g, g)` with depth >= 1 — a 23505 on
 * `group_closure_pkey`, surfaced as a bare `500 Internal server error`, with
 * the WHOLE import transaction rolled back and no indication of which line of
 * the bundle was at fault.
 *
 * A white/grey/black marking finds the cycle instead, and `CycleError` carries
 * the exact keys involved so the caller can name them to the operator.
 */

/** Thrown when the parent references form at least one cycle. */
export class CycleError extends Error {
  /** Keys of the items that sit on a cycle, in the order the walk closed it. */
  readonly cycle: string[];
  /** Every key involved in any cycle found (superset of `cycle`). */
  readonly allCyclicKeys: string[];

  constructor(cycle: string[], allCyclicKeys: string[]) {
    super(`Circular parent reference: ${cycle.join(' -> ')}`);
    this.name = 'CycleError';
    this.cycle = cycle;
    this.allCyclicKeys = allCyclicKeys;
  }
}

type Mark = 'grey' | 'black';

/**
 * Returns `items` reordered so that a parent always precedes its children.
 *
 * - Items whose `parentKey` is empty, or points at a key absent from `items`
 *   (an anchor already in the database), are roots.
 * - Items without a `uuidKey` value cannot be a parent; they are emitted in
 *   input order and never take part in a cycle.
 *
 * @throws {CycleError} as soon as a cycle is closed. Nothing is written by this
 *         function, so the caller can turn it into a 4xx before touching the
 *         database.
 */
export function topoSort<T extends Record<string, unknown>>(
  items: T[],
  uuidKey: string,
  parentKey: string,
): T[] {
  const byUuid = new Map<string, T>();
  for (const item of items) {
    const key = item[uuidKey];
    // First occurrence wins, matching the previous behaviour of Map(entries).
    if (typeof key === 'string' && key && !byUuid.has(key)) byUuid.set(key, item);
  }

  const sorted: T[] = [];
  const marks = new Map<string, Mark>();
  // Items with no usable key are tracked by identity so they are emitted once.
  const emittedAnonymous = new Set<T>();

  /** Explicit stack: a hand-edited bundle can be arbitrarily deep. */
  function visit(root: T): void {
    const rootKey = root[uuidKey];
    if (typeof rootKey !== 'string' || !rootKey) {
      if (!emittedAnonymous.has(root)) {
        emittedAnonymous.add(root);
        sorted.push(root);
      }
      return;
    }
    if (marks.get(rootKey) === 'black') return;

    // path doubles as the grey set, in order, so a closed cycle can be named.
    const path: string[] = [];
    const stack: Array<{ key: string; item: T; expanded: boolean }> = [
      { key: rootKey, item: root, expanded: false },
    ];

    while (stack.length > 0) {
      const frame = stack[stack.length - 1];

      if (frame.expanded) {
        stack.pop();
        path.pop();
        marks.set(frame.key, 'black');
        sorted.push(frame.item);
        continue;
      }

      const mark = marks.get(frame.key);
      if (mark === 'black') {
        stack.pop();
        continue;
      }
      if (mark === 'grey') {
        // Closed a cycle: everything from the first sighting of this key to the
        // top of the path is on it.
        const start = path.indexOf(frame.key);
        const cycle = start >= 0 ? [...path.slice(start), frame.key] : [frame.key, frame.key];
        throw new CycleError(cycle, [...new Set(cycle)]);
      }

      marks.set(frame.key, 'grey');
      path.push(frame.key);
      frame.expanded = true;

      const parentKeyValue = frame.item[parentKey];
      if (typeof parentKeyValue === 'string' && parentKeyValue) {
        const parent = byUuid.get(parentKeyValue);
        // A self-reference never reaches byUuid.get() as a distinct item, so it
        // is caught by the 'grey' branch above on the next iteration.
        if (parent) stack.push({ key: parentKeyValue, item: parent, expanded: false });
      }
    }
  }

  for (const item of items) visit(item);
  return sorted;
}

/**
 * Non-throwing variant: returns the keys that sit on a cycle without ordering
 * anything. Useful to report EVERY bad row of a bundle in one pass instead of
 * making the operator fix them one at a time.
 */
export function findCycles<T extends Record<string, unknown>>(
  items: T[],
  uuidKey: string,
  parentKey: string,
): string[] {
  const parentOf = new Map<string, string | null>();
  for (const item of items) {
    const key = item[uuidKey];
    if (typeof key !== 'string' || !key || parentOf.has(key)) continue;
    const parent = item[parentKey];
    parentOf.set(key, typeof parent === 'string' && parent ? parent : null);
  }

  const state = new Map<string, Mark>();
  const cyclic = new Set<string>();

  for (const start of parentOf.keys()) {
    if (state.has(start)) continue;
    const path: string[] = [];
    let cursor: string | null | undefined = start;

    while (cursor && !state.has(cursor) && parentOf.has(cursor)) {
      state.set(cursor, 'grey');
      path.push(cursor);
      cursor = parentOf.get(cursor) ?? null;
    }

    if (cursor && state.get(cursor) === 'grey') {
      // `cursor` is on the current path: everything from it onwards is a cycle.
      for (const key of path.slice(path.indexOf(cursor))) cyclic.add(key);
    }
    for (const key of path) state.set(key, 'black');
  }

  return [...cyclic];
}
