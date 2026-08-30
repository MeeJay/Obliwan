import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ChevronDown, ChevronRight, EyeOff, Lock, PenLine } from 'lucide-react';
import { scanTextForSecrets } from '@/utils/secretScan';
import type { CwmpParameter, ParamNode } from '@/types/acs';
import { buildParamTree } from '@/types/acs';

/**
 * The TR-069 parameter tree.
 *
 * ── §8.2 IS NOT A FOOTNOTE HERE, IT IS THE MAIN EVENT ───────────────────────
 * The last audit found the L2TP passwords of an entire fleet in a jsonb column
 * served to the UI. This tree renders the CWMP data model, which has
 * `InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Password`
 * as a STANDARD leaf. It is the same leak with a protocol behind it.
 *
 * Three locks, in order:
 *   1. `acs.api.ts` redacts on the way in, by path shape, before a component
 *      ever sees a value.
 *   2. `redacted` leaves render a chip and NOT a masked string — a masked
 *      secret still leaks its length, and length plus a vendor default is
 *      often enough.
 *   3. Every surviving value is passed through `scanTextForSecrets` at paint
 *      time. A hit replaces the value with a warning, because the point of a
 *      scanner is to catch the day the server starts sending something new.
 *
 * ── WHY A TREE AND NOT A TABLE ──────────────────────────────────────────────
 * §4.2 asks for "arbre de paramètres". A Vigor reports several thousand
 * parameters and their meaning is entirely positional: `...WANDevice.2...` and
 * `...WANDevice.1...` are two different uplinks and a flat list makes them
 * adjacent strings. The instance segments also sort NUMERICALLY here (10 after
 * 9, see `buildParamTree`), which a lexicographic table would get wrong in a
 * way nobody notices until an operator edits the wrong interface.
 */

const MAX_INITIAL_OPEN_DEPTH = 1;

export function ParameterTree({
  parameters,
  onEdit,
  filter,
}: {
  parameters: CwmpParameter[];
  /** Absent = read-only tree (no ACS_ADMIN, or the CPE is not writable). */
  onEdit?: (param: CwmpParameter) => void;
  filter: string;
}) {
  const { t } = useTranslation();

  const filtered = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return parameters;
    return parameters.filter((p) => p.path.toLowerCase().includes(needle));
  }, [parameters, filter]);

  const tree = useMemo(() => buildParamTree(filtered), [filtered]);

  if (parameters.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary py-10 text-center">
        <p className="text-sm text-text-muted">{t('acs.params.empty')}</p>
        <p className="mx-auto mt-1 max-w-lg text-xs text-text-muted">{t('acs.params.emptyHint')}</p>
      </div>
    );
  }

  if (filtered.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary py-10 text-center">
        <p className="text-sm text-text-muted">{t('acs.params.noMatch', { filter })}</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary p-2">
      <p className="mb-2 px-1 text-[11px] text-text-muted">
        {t('acs.params.shown', { shown: filtered.length, total: parameters.length })}
      </p>
      <ul className="min-w-[32rem]">
        {tree.map((node) => (
          <TreeNode
            key={node.path}
            node={node}
            depth={0}
            onEdit={onEdit}
            /* A filtered tree opens itself: hunting for a path and then having
               to expand six levels to reach it is the same as not finding it. */
            forceOpen={filter.trim().length > 0}
          />
        ))}
      </ul>
    </div>
  );
}

function TreeNode({
  node,
  depth,
  onEdit,
  forceOpen,
}: {
  node: ParamNode;
  depth: number;
  onEdit?: (param: CwmpParameter) => void;
  forceOpen: boolean;
}) {
  const [open, setOpen] = useState(depth < MAX_INITIAL_OPEN_DEPTH);
  const expanded = forceOpen || open;

  if (node.leaf && node.children.length === 0) {
    return <LeafRow param={node.leaf} name={node.name} depth={depth} onEdit={onEdit} />;
  }

  return (
    <li>
      <button
        onClick={() => setOpen((v) => !v)}
        style={{ paddingLeft: `${depth * 14 + 4}px` }}
        className="flex w-full items-center gap-1.5 rounded py-1 pr-2 text-left text-[12px] text-text-secondary hover:bg-bg-hover hover:text-text-primary"
      >
        {expanded ? <ChevronDown size={11} className="shrink-0" /> : <ChevronRight size={11} className="shrink-0" />}
        <span className="font-mono">{node.name}</span>
        <span className="ml-auto shrink-0 font-mono text-[10px] text-text-muted">{node.leafCount}</span>
      </button>
      {expanded && (
        <ul>
          {node.children.map((child) => (
            <TreeNode key={child.path} node={child} depth={depth + 1} onEdit={onEdit} forceOpen={forceOpen} />
          ))}
        </ul>
      )}
    </li>
  );
}

function LeafRow({
  param,
  name,
  depth,
  onEdit,
}: {
  param: CwmpParameter;
  name: string;
  depth: number;
  onEdit?: (param: CwmpParameter) => void;
}) {
  const { t } = useTranslation();

  // Lock 3 — the scan at paint time. `redacted` values never reach here with a
  // body, so a hit means the server sent something new and unmasked.
  const leaked = param.value !== null && scanTextForSecrets(param.value, 1).length > 0;

  return (
    <li
      className="flex items-center gap-2 rounded py-1 pr-2 text-[12px] hover:bg-bg-hover"
      style={{ paddingLeft: `${depth * 14 + 18}px` }}
      title={param.path}
    >
      <span className="shrink-0 font-mono text-text-secondary">{name}</span>

      {param.redacted ? (
        <span className="ml-auto inline-flex shrink-0 items-center gap-1 rounded border border-border bg-bg-tertiary px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-text-muted">
          <EyeOff size={10} />
          {t('acs.params.withheld')}
        </span>
      ) : leaked ? (
        <span className="ml-auto inline-flex shrink-0 items-center gap-1 rounded border border-status-ssl-expired/60 bg-status-ssl-expired/15 px-1.5 py-0.5 text-[10px] text-status-ssl-expired">
          <EyeOff size={10} />
          {t('acs.params.leakGuard')}
        </span>
      ) : (
        <span className="ml-auto max-w-[24rem] truncate font-mono text-[11px] text-text-primary">
          {param.value === null ? <span className="text-text-muted">{t('acs.params.emptyValue')}</span> : param.value}
        </span>
      )}

      {param.valueType && (
        <span className="hidden shrink-0 font-mono text-[10px] text-text-muted sm:inline">
          {param.valueType}
        </span>
      )}

      {param.writable ? (
        onEdit ? (
          <button
            onClick={() => onEdit(param)}
            title={t('acs.params.edit')}
            className="shrink-0 rounded p-0.5 text-text-muted hover:bg-bg-active hover:text-accent"
          >
            <PenLine size={11} />
          </button>
        ) : (
          <span className="w-[18px] shrink-0" />
        )
      ) : (
        <Lock size={10} className="shrink-0 text-text-muted" aria-label={t('acs.params.readOnly')} />
      )}
    </li>
  );
}
