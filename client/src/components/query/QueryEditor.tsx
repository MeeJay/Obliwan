import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, Braces, Lightbulb, ShieldAlert } from 'lucide-react';
import { cn } from '@/utils/cn';
import {
  NCM_SCHEMA_FIELDS,
  SCHEMA_INTROSPECTED,
  completionsFor,
  type Completion,
} from './ncmSchema';
import type { QueryError } from '@/types/query';

/**
 * The DSL editor, with completion driven by the NCM schema (§5/M9).
 *
 * ┌─ WHY A TEXTAREA AND NOT A CODE-EDITOR DEPENDENCY ────────────────────────┐
 * │ §6.1 lists the dependencies this project may add, and a 400 kB editor is │
 * │ not among them — the client bundle is already 1201 kB in one chunk and   │
 * │ that is written down as open debt. A textarea with a completion popup    │
 * │ gets the whole value of §5/M9 ("page Requêtes avec autocomplétion") at a │
 * │ cost of zero bytes of dependency, and it keeps working in a browser with │
 * │ a screen reader, which a canvas-based editor does not.                   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── THE EDITOR OFFERS, IT NEVER REWRITES ───────────────────────────────────
 * No auto-insert on a single match, no auto-closing quotes, no reformat on
 * blur. An audit query is a sentence somebody will paste into a change ticket;
 * an editor that silently edited it would make the ticket describe a query
 * nobody ran. Completion is Tab or Enter on an explicitly highlighted item, or
 * a click. Escape closes without touching the text.
 *
 * ── AND IT DOES NOT VALIDATE AS YOU TYPE ────────────────────────────────────
 * Validation is a round trip to the Chevrotain parser. Firing it per keystroke
 * makes the server parse a hundred incomplete expressions per query and makes
 * the editor flash red at every half-typed word. The error shown here is the
 * one that came back from the last RUN or the explicit Check button.
 */

const MAX_VISIBLE = 8;

export function QueryEditor({
  value,
  onChange,
  onRun,
  error,
  disabled,
  className,
}: {
  value: string;
  onChange: (next: string) => void;
  onRun: () => void;
  error: QueryError | null;
  disabled?: boolean;
  className?: string;
}) {
  const { t } = useTranslation();
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  /** Set by our own onChange. Distinguishes "the operator typed" from "the
   *  parent replaced the text" (an example button, a saved query being
   *  loaded). Without it, the effect below would close the popup that the very
   *  next keystroke just opened. */
  const selfEditedRef = useRef(false);
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<Completion[]>([]);
  const [from, setFrom] = useState(0);
  const [active, setActive] = useState(0);

  const refresh = useCallback(() => {
    const el = textareaRef.current;
    if (!el) return;
    const caret = el.selectionStart ?? el.value.length;
    const { items: next, from: start } = completionsFor(el.value, caret);
    setItems(next.slice(0, 60));
    setFrom(start);
    setActive(0);
    setOpen(next.length > 0);
  }, []);

  const insert = useCallback(
    (completion: Completion) => {
      const el = textareaRef.current;
      if (!el) return;
      const caret = el.selectionStart ?? el.value.length;
      const next = `${value.slice(0, from)}${completion.value} ${value.slice(caret)}`;
      onChange(next);
      setOpen(false);
      // The caret has to land after the inserted token, on the next frame —
      // React has not re-rendered the textarea yet at this point.
      const at = from + completion.value.length + 1;
      requestAnimationFrame(() => {
        el.focus();
        el.setSelectionRange(at, at);
      });
    },
    [value, from, onChange],
  );

  const onKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      // Ctrl/Cmd+Enter runs, whatever the popup is doing.
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        setOpen(false);
        onRun();
        return;
      }
      if (e.key === ' ' && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        refresh();
        return;
      }
      if (!open || items.length === 0) return;

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setActive((i) => (i + 1) % items.length);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setActive((i) => (i - 1 + items.length) % items.length);
      } else if (e.key === 'Tab' || e.key === 'Enter') {
        e.preventDefault();
        insert(items[active]);
      } else if (e.key === 'Escape') {
        e.preventDefault();
        setOpen(false);
      }
    },
    [open, items, active, insert, onRun, refresh],
  );

  // Close the popup when the value is replaced from OUTSIDE (an example button,
  // a saved query being loaded): those suggestions were for the old text. A
  // change the operator typed must not close it — that is the case this ref
  // exists to exclude.
  useEffect(() => {
    if (selfEditedRef.current) { selfEditedRef.current = false; return; }
    setOpen(false);
  }, [value]);

  const visible = useMemo(() => {
    const start = Math.max(0, Math.min(active - MAX_VISIBLE + 1, items.length - MAX_VISIBLE));
    return { start, slice: items.slice(start, start + MAX_VISIBLE) };
  }, [items, active]);

  return (
    <div className={cn('relative', className)}>
      <div className="flex items-center gap-2 rounded-t-lg border border-b-0 border-border bg-bg-tertiary px-3 py-1.5">
        <Braces size={13} className="text-text-muted" />
        <span className="text-[11px] uppercase tracking-wider text-text-muted">
          {t('query.editor.title')}
        </span>
        <span className="ml-auto font-mono text-[10px] text-text-muted">
          {SCHEMA_INTROSPECTED
            ? t('query.editor.fieldCount', { count: NCM_SCHEMA_FIELDS.length })
            : t('query.editor.noSchema')}
        </span>
      </div>

      <textarea
        ref={textareaRef}
        value={value}
        disabled={disabled}
        spellCheck={false}
        rows={4}
        onChange={(e) => { selfEditedRef.current = true; onChange(e.target.value); }}
        onKeyUp={(e) => {
          // Refresh on the keys that change the token under the caret, not on
          // the navigation keys the popup itself consumes.
          if (!['ArrowUp', 'ArrowDown', 'Escape', 'Enter', 'Tab'].includes(e.key)) refresh();
        }}
        onKeyDown={onKeyDown}
        onBlur={() => setTimeout(() => setOpen(false), 120)}
        placeholder={t('query.editor.placeholder')}
        className="w-full rounded-b-lg border border-border bg-bg-secondary px-3 py-2 font-mono text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
      />

      {open && items.length > 0 && (
        <ul className="absolute left-3 z-20 mt-[-0.25rem] max-h-64 w-[32rem] max-w-[calc(100%-1.5rem)] overflow-y-auto rounded-md border border-border bg-bg-secondary shadow-lg">
          {visible.slice.map((item, i) => {
            const index = visible.start + i;
            return (
              <li key={`${item.category}:${item.value}`}>
                <button
                  type="button"
                  // `mousedown` and not `click`: the textarea's blur fires
                  // first and would close the popup before a click landed.
                  onMouseDown={(e) => { e.preventDefault(); insert(item); }}
                  onMouseEnter={() => setActive(index)}
                  className={cn(
                    'flex w-full items-center gap-2 px-2.5 py-1.5 text-left',
                    index === active ? 'bg-accent/15' : 'hover:bg-bg-hover',
                  )}
                >
                  <span
                    className={cn(
                      'rounded border px-1 py-px font-mono text-[9px] uppercase tracking-wider',
                      item.category === 'field' ? 'border-accent/40 bg-accent/10 text-accent'
                        : item.category === 'operator' ? 'border-border bg-bg-tertiary text-text-secondary'
                          : item.category === 'value' ? 'border-status-up/40 bg-status-up/10 text-status-up'
                            : 'border-border bg-bg-tertiary text-text-muted',
                    )}
                  >
                    {t(`query.editor.category.${item.category}`)}
                  </span>
                  <span className="font-mono text-[12px] text-text-primary">{item.label}</span>
                  <span className="ml-auto truncate font-mono text-[10px] text-text-muted">
                    {item.detail}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      )}

      <div className="mt-1 flex flex-wrap items-center gap-2">
        <span className="inline-flex items-center gap-1 text-[11px] text-text-muted">
          <Lightbulb size={11} />
          {t('query.editor.hint')}
        </span>
      </div>

      {!SCHEMA_INTROSPECTED && (
        <p className="mt-2 flex items-start gap-1.5 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 px-2.5 py-1.5 text-[12px] text-status-ssl-warning">
          <AlertTriangle size={12} className="mt-0.5 shrink-0" />
          {t('query.editor.noSchemaHint')}
        </p>
      )}

      {error && (
        <div
          className={cn(
            'mt-2 rounded-md border px-3 py-2 text-[12px]',
            error.kind === 'path_not_allowed'
              ? 'border-status-ssl-expired/60 bg-status-ssl-expired/10 text-status-ssl-expired'
              : 'border-status-down/50 bg-status-down/10 text-status-down',
          )}
        >
          <p className="flex items-center gap-1.5 font-medium">
            <ShieldAlert size={12} />
            {t(`query.error.kind.${error.kind}`)}
          </p>
          <p className="mt-0.5 font-mono">{error.message}</p>
          {error.offset !== null && (
            <p className="mt-1 font-mono text-[11px] opacity-80">
              {t('query.error.at', { offset: error.offset })}
              {'  '}
              <span className="whitespace-pre">
                {value.slice(Math.max(0, error.offset - 24), error.offset)}
                <span className="bg-status-ssl-expired/30">
                  {value.slice(error.offset, error.offset + Math.max(1, error.length ?? 1))}
                </span>
              </span>
            </p>
          )}
        </div>
      )}
    </div>
  );
}
