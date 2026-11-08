// Shared console building blocks: one icon set, notices that stay until
// dismissed, status badges with consistent colours, and tabs. Display only:
// nothing here decides authorization; the API does.
import { useEffect, useState, type ReactNode } from 'react';

const ICON_PATHS = {
  overview: 'M4 4h7v7H4zM13 4h7v4h-7zM13 10h7v10h-7zM4 13h7v7H4z',
  authority: 'M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6zM9 12l2 2 4-4',
  profile: 'M7 3h7l4 4v14H7zM14 3v4h4M10 12h5M10 16h5',
  request: 'M4 13l2-8h12l2 8M4 13v6h16v-6M4 13h5l1 2h4l1-2h5',
  certificate: 'M5 4h14v11H5zM8 8h8M8 11h5M12 15l-2 6 2-1 2 1-2-6',
  revocation: 'M12 3a9 9 0 100 18 9 9 0 000-18zM5.6 5.6l12.8 12.8',
  audit: 'M12 7v5l3 2M3 12a9 9 0 109-9 9 9 0 00-7 3.3M3 4v4h4',
  refresh: 'M20 11a8 8 0 10-2.3 6M20 5v6h-6',
  signOut: 'M15 4h4v16h-4M10 8l-4 4 4 4M6 12h10',
  search: 'M11 4a7 7 0 100 14 7 7 0 000-14zM20 20l-4-4',
  copy: 'M9 9h11v11H9zM5 15V4h11',
  link: 'M10 14a4 4 0 006 0l3-3a4 4 0 00-6-6l-1 1M14 10a4 4 0 00-6 0l-3 3a4 4 0 006 6l1-1',
  download: 'M12 4v11M7 10l5 5 5-5M4 19h16',
  plus: 'M12 5v14M5 12h14',
  close: 'M6 6l12 12M18 6L6 18',
  check: 'M5 12l4 4 10-10',
  alert: 'M12 4l9 16H3zM12 10v4M12 17v.5',
  info: 'M12 3a9 9 0 100 18 9 9 0 000-18zM12 11v6M12 7.5v.5',
  chevron: 'M9 6l6 6-6 6',
  key: 'M14 4a6 6 0 11-4.7 9.7L4 19v1h3v-2h2v-2h2l1.3-1.3A6 6 0 0114 4zM16 8v.5',
  publish: 'M12 16V4M7 9l5-5 5 5M5 14v6h14v-6',
  filter: 'M4 5h16l-6 8v6l-4-2v-4z',
} as const;

export type IconName = keyof typeof ICON_PATHS;

export function Icon({ name, size = 18, title }: { name: IconName; size?: number; title?: string }) {
  return <svg className="icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
    strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round" aria-hidden={title ? undefined : true}
    role={title ? 'img' : undefined} aria-label={title}>
    <path d={ICON_PATHS[name]} />
  </svg>;
}

export type NoticeTone = 'error' | 'warning' | 'success' | 'info';

// A notice that stays until the person dismisses it or a newer one replaces
// it, so an error is never lost to a reload.
export function Notice({ tone, children, onDismiss, action }: {
  tone: NoticeTone; children: ReactNode; onDismiss?: () => void; action?: ReactNode;
}) {
  const icon: IconName = tone === 'error' || tone === 'warning' ? 'alert' : tone === 'success' ? 'check' : 'info';
  return <div className={`ui-notice ui-notice-${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
    <Icon name={icon} />
    <div className="ui-notice-body">{children}</div>
    {action}
    {onDismiss && <button type="button" className="ui-icon-button" aria-label="Dismiss message" onClick={onDismiss}><Icon name="close" size={16} /></button>}
  </div>;
}

const STATUS_TONES: Record<string, string> = {
  ACTIVE: 'good', APPROVED: 'good', ISSUED: 'good', SIGNED: 'good', PUBLISHED: 'good', allow: 'good', KEY_ATTESTED: 'info',
  SUBMITTED: 'info', PROPOSED: 'info', DRAFT: 'neutral', ISSUING: 'info', REVOCATION_REQUESTED: 'warn',
  SUSPENDED: 'warn', RECONCILIATION_REQUIRED: 'warn', SUPERSEDED: 'neutral', persisted: 'neutral',
  REJECTED: 'bad', REVOKED: 'bad', RETIRED: 'neutral', deny: 'bad', EXPIRED: 'bad',
  CURRENT: 'good', RENEWAL_DUE: 'warn', NO_CRL: 'neutral',
};

export function StatusBadge({ status }: { status: string }) {
  return <span className={`ui-badge ui-badge-${STATUS_TONES[status] ?? 'neutral'}`}>{status}</span>;
}

export function Tabs<T extends string>({ label, tabs, value, onChange }: {
  label: string; tabs: { id: T; label: string; count?: number }[]; value: T; onChange: (id: T) => void;
}) {
  return <div className="ui-tabs" role="tablist" aria-label={label}>{tabs.map(tab =>
    <button key={tab.id} type="button" role="tab" aria-selected={tab.id === value}
      className={tab.id === value ? 'ui-tab active' : 'ui-tab'} onClick={() => onChange(tab.id)}>
      {tab.label}{tab.count !== undefined && <span className="ui-tab-count">{tab.count}</span>}
    </button>)}</div>;
}

export function Card({ title, actions, children, id, description }: {
  title: string; actions?: ReactNode; children: ReactNode; id?: string; description?: ReactNode;
}) {
  return <section className="ui-card" aria-labelledby={id}>
    <div className="ui-card-header"><div><h3 id={id}>{title}</h3>{description && <p>{description}</p>}</div>{actions && <div className="ui-card-actions">{actions}</div>}</div>
    <div className="ui-card-body">{children}</div>
  </section>;
}

// A select-all checkbox that shows the partial state of the rows it covers.
export function HeaderCheckbox({ state, label, onChange }: { state: 'none' | 'some' | 'all'; label: string; onChange: () => void }) {
  return <input type="checkbox" aria-label={label} checked={state === 'all'} ref={element => { if (element) element.indeterminate = state === 'some'; }} onChange={onChange} />;
}

// A collapsible section that opens itself when filters become active and
// otherwise stays as the person left it (clearing a filter never hides it).
export function Disclosure({ summary, active, className, children }: {
  summary: ReactNode; active?: boolean; className?: string; children: ReactNode;
}) {
  const [open, setOpen] = useState(Boolean(active));
  useEffect(() => { if (active) setOpen(true); }, [active]);
  return <details className={className ? `ui-disclosure ${className}` : 'ui-disclosure'} open={open}
    onToggle={event => setOpen((event.currentTarget as HTMLDetailsElement).open)}>
    <summary>{summary}</summary>{children}
  </details>;
}
