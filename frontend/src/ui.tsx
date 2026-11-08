// Shared console building blocks: one icon set, notices that stay until
// dismissed, status badges with consistent colours, and tabs. Display only:
// nothing here decides authorization; the API does.
import { Fragment, useEffect, useState, type ReactNode } from 'react';
import { CATEGORY_LABELS, describeEvent, describeOutcome, humanizeStatus, relativeTime, type EventCategory } from './labels';

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
  policy: 'M6 3h12v18H6zM9 12l2 2 4-4M9 7h6',
  arrow: 'M5 12h14M13 6l6 6-6 6',
  command: 'M9 6a3 3 0 10-3 3h12a3 3 0 10-3-3v12a3 3 0 103-3H6a3 3 0 103 3z',
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
  ACTIVE: 'good', APPROVED: 'good', ISSUED: 'good', SIGNED: 'good', PUBLISHED: 'good', CURRENT: 'good', allow: 'good',
  accepted: 'good', persisted: 'good', created: 'good', published: 'good', signed: 'good',
  KEY_ATTESTED: 'info', SUBMITTED: 'info', PROPOSED: 'info', ISSUING: 'info', SIGNING: 'info', RECEIVED: 'info',
  CSR_VALIDATED: 'info', AUTHORIZED: 'info', SERIAL_RESERVED: 'info',
  REVOCATION_REQUESTED: 'warn', SUSPENDED: 'warn', RECONCILIATION_REQUIRED: 'warn', RENEWAL_DUE: 'warn',
  REJECTED: 'bad', REVOKED: 'bad', EXPIRED: 'bad', FAILED: 'bad', deny: 'bad', failed: 'bad', rejected: 'bad',
  DRAFT: 'neutral', SUPERSEDED: 'neutral', RETIRED: 'neutral', NO_CRL: 'neutral',
};

/** A status as words with a coloured dot; the raw code is kept as a tooltip and data attribute. */
export function StatusBadge({ status }: { status: string }) {
  return <span className={`ui-badge ui-badge-${STATUS_TONES[status] ?? 'neutral'}`} title={status} data-status={status}>
    <span className="ui-badge-dot" aria-hidden="true" />{humanizeStatus(status)}
  </span>;
}

const CATEGORY_ICONS: Record<EventCategory, IconName> = {
  certificate: 'certificate', request: 'request', signing: 'key', crl: 'revocation',
  profile: 'profile', authority: 'authority', policy: 'policy', other: 'info',
};

/** An audit event type as a label with its category; the code is shown beneath. */
export function EventLabel({ type }: { type: string }) {
  const event = describeEvent(type);
  return <span className="ui-event">
    <span className={`ui-event-icon ui-cat-${event.category}`} title={CATEGORY_LABELS[event.category]}><Icon name={CATEGORY_ICONS[event.category]} size={15} /></span>
    <span className="ui-event-text"><span className="ui-event-label">{event.label}</span><code className="ui-event-code">{event.code.split('.').map((part, index) => <Fragment key={index}>{index > 0 && <>.<wbr /></>}{part}</Fragment>)}</code></span>
  </span>;
}

/** The audit decision column, whatever its shape, as badges. */
export function OutcomeBadge({ decision }: { decision: string }) {
  const outcome = describeOutcome(decision);
  switch (outcome.kind) {
    case 'decision': return <StatusBadge status={outcome.status} />;
    case 'result': return <StatusBadge status={outcome.status} />;
    case 'transition': return <span className="ui-transition" aria-label={`${humanizeStatus(outcome.from)} to ${humanizeStatus(outcome.to)}`}>
      <StatusBadge status={outcome.from} /><Icon name="arrow" size={14} /><StatusBadge status={outcome.to} /></span>;
    case 'reference': return <span className="ui-transition"><StatusBadge status={outcome.status} /><code className="ui-ref" title={outcome.reference}>{outcome.reference.length > 13 ? `${outcome.reference.slice(0, 8)}…` : outcome.reference}</code></span>;
    default: return <span className="ui-sub">{outcome.text}</span>;
  }
}

/** A small label with a tone, for values that are not workflow statuses. */
export function Tag({ tone = 'neutral', children, title }: { tone?: 'good' | 'info' | 'warn' | 'bad' | 'neutral'; children: ReactNode; title?: string }) {
  return <span className={`ui-badge ui-badge-soft ui-badge-${tone}`} title={title}><span className="ui-badge-dot" aria-hidden="true" />{children}</span>;
}

/** A relative time that shows the exact local time on hover. */
export function TimeAgo({ value, now }: { value: string; now: Date }) {
  const date = new Date(value);
  const exact = Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
  return <time dateTime={value} title={exact} className="ui-time"><span>{relativeTime(value, now)}</span><small>{exact}</small></time>;
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

/** A row of toggle chips with counts; one value is active at a time. */
export function FilterChips<T extends string>({ label, options, value, onChange }: {
  label: string; options: { id: T; label: string; count: number; tone?: string }[]; value: T; onChange: (id: T) => void;
}) {
  return <div className="ui-chips" role="group" aria-label={label}>{options.map(option =>
    <button key={option.id} type="button" aria-pressed={option.id === value} disabled={option.count === 0 && option.id !== value}
      className={`ui-chip-toggle${option.id === value ? ' on' : ''}${option.tone ? ` ui-tone-${option.tone}` : ''}`} onClick={() => onChange(option.id === value ? options[0].id : option.id)}>
      {option.tone && <span className="ui-badge-dot" aria-hidden="true" />}{option.label}<span className="ui-chip-count">{option.count}</span>
    </button>)}</div>;
}
