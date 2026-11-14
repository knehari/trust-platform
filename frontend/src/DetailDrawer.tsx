import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Icon, type IconName } from './ui';

/**
 * A slide-over detail panel: a sticky header that names the record and its
 * state, a highlighted summary, grouped facts with one-click copy, optional
 * previous/next navigation (buttons, ↑/↓ or j/k), and a footer note.
 * Display only: it shows the metadata the API returned.
 */
export function DetailDrawer({ label, eyebrow, title, subtitle, icon, tone, badges, actions, summary, children, note, closeLabel, onClose, onPrevious, onNext, position, labelledBy }: {
  label?: string; labelledBy?: string; eyebrow: string; title: ReactNode; subtitle?: ReactNode; icon: IconName; tone: string;
  badges?: ReactNode; actions?: ReactNode; summary?: ReactNode; children: ReactNode; note?: ReactNode; closeLabel: string; onClose: () => void;
  onPrevious?: (() => void) | null; onNext?: (() => void) | null; position?: string;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current;
    if (element && !element.open) element.showModal();
    return () => element?.close();
  }, []);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement;
      if (target.closest('input, textarea, select')) return;
      if ((event.key === 'ArrowDown' || event.key === 'j') && onNext) { event.preventDefault(); onNext(); }
      if ((event.key === 'ArrowUp' || event.key === 'k') && onPrevious) { event.preventDefault(); onPrevious(); }
    };
    const element = dialog.current;
    element?.addEventListener('keydown', onKey);
    return () => element?.removeEventListener('keydown', onKey);
  }, [onNext, onPrevious]);
  return <dialog ref={dialog} className="certificate-dialog ui-drawer" aria-label={labelledBy ? undefined : label} aria-labelledby={labelledBy} onClose={onClose}
    onClick={event => { if (event.target === dialog.current) dialog.current?.close(); }}>
    <header className={`ui-drawer-head ui-tone-${tone}`}>
      <div className="ui-drawer-bar">
        <span className="ui-drawer-eyebrow">{eyebrow}</span>
        <div className="ui-drawer-tools">
          {(onPrevious !== undefined || onNext !== undefined) && <div className="ui-drawer-nav">
            {position && <span className="ui-drawer-position">{position}</span>}
            <button type="button" className="ui-icon-button" aria-label="Previous record" title="Previous (↑ or k)" disabled={!onPrevious} onClick={() => onPrevious?.()}><Icon name="chevron" size={16} /></button>
            <button type="button" className="ui-icon-button" aria-label="Next record" title="Next (↓ or j)" disabled={!onNext} onClick={() => onNext?.()}><Icon name="chevron" size={16} /></button>
          </div>}
          <button type="button" className="ui-icon-button" aria-label={closeLabel} title="Close (Esc)" onClick={() => dialog.current?.close()}><Icon name="close" size={18} /></button>
        </div>
      </div>
      <div className="ui-drawer-title">
        <span className="ui-drawer-icon"><Icon name={icon} size={22} /></span>
        <div className="ui-drawer-heading"><h2 id={labelledBy}>{title}</h2>{subtitle && <div className="ui-drawer-subtitle">{subtitle}</div>}</div>
      </div>
      {badges && <div className="ui-drawer-badges">{badges}</div>}
      {actions && <div className="ui-drawer-actions">{actions}</div>}
    </header>
    <div className="ui-drawer-body">
      {summary && <div className="ui-drawer-summary">{summary}</div>}
      {children}
      {note && <div className="ui-drawer-note"><Icon name="info" size={16} /><p>{note}</p></div>}
    </div>
  </dialog>;
}

export function DrawerSection({ title, children }: { title: string; children: ReactNode }) {
  return <section className="ui-drawer-section"><h3>{title}</h3><dl className="ui-facts">{children}</dl></section>;
}

/** One labelled fact; `copy` adds a copy button that confirms in place. */
export function Fact({ label, children, copy, mono }: { label: string; children: ReactNode; copy?: string; mono?: boolean }) {
  const [copied, setCopied] = useState<'ok' | 'fail' | null>(null);
  useEffect(() => { if (!copied) return; const timer = window.setTimeout(() => setCopied(null), 1600); return () => window.clearTimeout(timer); }, [copied]);
  return <div className="ui-fact">
    <dt>{label}</dt>
    <dd className={mono ? 'mono' : undefined}>
      <span className="ui-fact-value">{children}</span>
      {copy && <button type="button" className={`ui-copy${copied === 'ok' ? ' done' : ''}`} aria-label={`Copy ${label.toLowerCase()}`}
        onClick={() => { navigator.clipboard.writeText(copy).then(() => setCopied('ok'), () => setCopied('fail')); }}>
        <Icon name={copied === 'ok' ? 'check' : 'copy'} size={14} />{copied === 'ok' ? 'Copied' : copied === 'fail' ? 'Select to copy' : 'Copy'}
      </button>}
    </dd>
  </div>;
}

/** A copy button for the whole record as JSON, with in-place feedback. */
export function CopyJsonButton({ json, label = 'Copy metadata JSON' }: { json: string; label?: string }) {
  const [state, setState] = useState<'idle' | 'ok' | 'fail'>('idle');
  useEffect(() => { if (state === 'idle') return; const timer = window.setTimeout(() => setState('idle'), 1800); return () => window.clearTimeout(timer); }, [state]);
  return <button type="button" className="ui-button ui-button-secondary ui-button-sm" onClick={() => { navigator.clipboard.writeText(json).then(() => setState('ok'), () => setState('fail')); }}>
    <Icon name={state === 'ok' ? 'check' : 'copy'} size={14} />{state === 'ok' ? 'Copied' : state === 'fail' ? 'Copy failed' : label}
    <span className="sr-only" role="status">{state === 'ok' ? 'Metadata JSON copied.' : state === 'fail' ? 'Could not copy metadata JSON.' : ''}</span>
  </button>;
}
