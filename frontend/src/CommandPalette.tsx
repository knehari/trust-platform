import { useEffect, useMemo, useRef, useState } from 'react';
import { Icon, type IconName } from './ui';

export interface PaletteItem { id: string; group: string; label: string; hint?: string; icon: IconName; run: () => void }

/**
 * Jump to a section or an authority from the keyboard (Ctrl/Cmd + K).
 * Navigation only: every view still loads through the API with the
 * signed-in user's token.
 */
export function CommandPalette({ items, open, onClose }: { items: PaletteItem[]; open: boolean; onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);

  useEffect(() => {
    const element = dialog.current;
    if (!element) return;
    if (open && !element.open) { setQuery(''); setActive(0); element.showModal(); }
    if (!open && element.open) element.close();
  }, [open]);

  const matches = useMemo(() => {
    const terms = query.trim().toLowerCase().split(/\s+/u).filter(Boolean);
    return items.filter(item => terms.every(term => `${item.label} ${item.hint ?? ''} ${item.group}`.toLowerCase().includes(term)));
  }, [items, query]);

  function choose(item: PaletteItem | undefined) {
    if (!item) return;
    onClose();
    item.run();
  }

  let lastGroup = '';
  return <dialog ref={dialog} className="ui-palette" aria-label="Go to" onClose={onClose}
    onClick={event => { if (event.target === dialog.current) onClose(); }}>
    <div className="ui-palette-input"><Icon name="search" />
      <input autoFocus value={query} placeholder="Go to a section or an authority…" aria-label="Search sections and authorities"
        role="combobox" aria-expanded="true" aria-controls="ui-palette-list" aria-activedescendant={matches[active] ? `palette-${matches[active].id}` : undefined}
        onChange={event => { setQuery(event.target.value); setActive(0); }}
        onKeyDown={event => {
          if (event.key === 'ArrowDown') { event.preventDefault(); setActive(value => Math.min(value + 1, matches.length - 1)); }
          else if (event.key === 'ArrowUp') { event.preventDefault(); setActive(value => Math.max(value - 1, 0)); }
          else if (event.key === 'Enter') { event.preventDefault(); choose(matches[active]); }
        }} />
      <span className="ui-kbd">Esc</span>
    </div>
    {matches.length === 0 ? <p className="ui-palette-empty">Nothing matches “{query}”.</p>
      : <ul className="ui-palette-list" id="ui-palette-list" role="listbox">{matches.map((item, index) => {
        const header = item.group !== lastGroup ? item.group : null;
        lastGroup = item.group;
        return <li key={item.id} role="presentation">
          {header && <div className="ui-palette-group" role="presentation">{header}</div>}
          <div id={`palette-${item.id}`} role="option" aria-selected={index === active} className="ui-palette-item"
            onMouseMove={() => setActive(index)} onClick={() => choose(item)}>
            <Icon name={item.icon} size={16} />{item.label}{item.hint && <small>{item.hint}</small>}
          </div>
        </li>;
      })}</ul>}
    <div className="ui-palette-foot"><span><span className="ui-kbd">↑</span> <span className="ui-kbd">↓</span> to move</span><span><span className="ui-kbd">Enter</span> to open</span></div>
  </dialog>;
}
