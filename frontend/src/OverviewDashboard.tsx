import { useEffect, useMemo, useState } from 'react';
import { ApiError, apiGet, type AuditEvent, type Certificate, type CertificateAuthority } from './api';
import type { Application } from './RequestsPanel';
import type { Section } from './navigation';
import { activityByDay, attentionEvents, certificateHealth, expiryBuckets, type Bucket } from './dashboard';
import { Icon, StatusBadge, type IconName } from './ui';

interface CrlStatus { latest_crl_number: number | null; next_update: string | null; renewal_due: boolean; expired: boolean }

interface QueueItem { id: string; tone: 'bad' | 'warn' | 'info'; icon: IconName; count: number; title: string; detail: string; action: string; section: Section }

/**
 * The selected authority at a glance: what needs doing now, certificate
 * health, upcoming expiries and recent activity. Figures come from the rows
 * the console loaded and from the API's own status routes.
 */
export function OverviewDashboard({ ca, certificates, auditEvents, now, token, isOfficer, isRequester, isReader, onNavigate, onUnauthorized, certificatesComplete, auditComplete }: {
  ca: CertificateAuthority; certificates: Certificate[]; auditEvents: AuditEvent[]; now: number; token: string;
  isOfficer: boolean; isRequester: boolean; isReader: boolean; onNavigate: (section: Section) => void; onUnauthorized: () => void;
  certificatesComplete: boolean; auditComplete: boolean;
}) {
  const [applications, setApplications] = useState<Application[] | null>(null);
  const [crl, setCrl] = useState<CrlStatus | null>(null);
  const [pending, setPending] = useState(0);
  const base = `/v1/cas/${encodeURIComponent(ca.ca_id)}`;

  useEffect(() => {
    const controller = new AbortController();
    // A refused or failed status route only hides its queue items; it never blocks the dashboard.
    const quiet = (failure: unknown) => { if (failure instanceof ApiError && failure.status === 401 && !controller.signal.aborted) onUnauthorized(); };
    const done = () => { if (!controller.signal.aborted) setPending(value => value - 1); };
    setApplications(null); setCrl(null);
    const wantsApplications = isOfficer || isRequester;
    const wantsCrl = isReader || isOfficer;
    setPending(Number(wantsApplications) + Number(wantsCrl));
    if (wantsApplications) apiGet<Application[]>(`${base}/certificate-applications`, token, controller.signal).then(setApplications).catch(quiet).finally(done);
    if (wantsCrl) apiGet<CrlStatus>(`${base}/crl-status`, token, controller.signal).then(setCrl).catch(quiet).finally(done);
    return () => controller.abort();
  }, [base, token, isOfficer, isRequester, isReader]);

  const health = useMemo(() => certificateHealth(certificates, now), [certificates, now]);
  const expiries = useMemo(() => expiryBuckets(certificates, now, 12), [certificates, now]);
  const activity = useMemo(() => activityByDay(auditEvents, now, 14), [auditEvents, now]);
  const attention = useMemo(() => attentionEvents(auditEvents, now), [auditEvents, now]);
  const events14 = activity.reduce((sum, day) => sum + day.count, 0);
  const denied14 = activity.reduce((sum, day) => sum + day.extra, 0);

  const count = (status: string) => applications?.filter(row => row.status === status).length ?? 0;
  const queue: QueueItem[] = [];
  if (isOfficer && applications) {
    if (count('SUBMITTED')) queue.push({ id: 'decide', tone: 'warn', icon: 'request', count: count('SUBMITTED'), title: 'Requests awaiting your decision', detail: 'Approve or reject each certificate application.', action: 'Review requests', section: 'requests' });
    if (count('REVOCATION_REQUESTED')) queue.push({ id: 'revoke', tone: 'warn', icon: 'revocation', count: count('REVOCATION_REQUESTED'), title: 'Revocations awaiting a decision', detail: 'Approved revocations appear on the next CRL.', action: 'Review revocations', section: 'requests' });
    if (count('APPROVED')) queue.push({ id: 'issue', tone: 'info', icon: 'certificate', count: count('APPROVED'), title: 'Approved requests ready to issue', detail: 'The laboratory signer signs each certificate once.', action: 'Issue certificates', section: 'requests' });
  } else if (isRequester && applications) {
    const open = count('SUBMITTED') + count('APPROVED') + count('REVOCATION_REQUESTED');
    if (open) queue.push({ id: 'mine', tone: 'info', icon: 'request', count: open, title: 'Your requests in progress', detail: 'Submitted, approved or awaiting a revocation decision.', action: 'Open requests', section: 'requests' });
  }
  if (crl && (isOfficer || isReader)) {
    if (crl.expired) queue.push({ id: 'crl', tone: 'bad', icon: 'revocation', count: 1, title: 'The CRL has expired', detail: 'Relying parties may reject certificates until a new CRL is published.', action: isOfficer ? 'Publish CRL' : 'Open CRLs', section: 'revocation' });
    else if (crl.latest_crl_number === null) queue.push({ id: 'crl', tone: 'warn', icon: 'revocation', count: 1, title: 'No CRL published yet', detail: 'Publish one so relying parties can check revocation.', action: isOfficer ? 'Publish CRL' : 'Open CRLs', section: 'revocation' });
    else if (crl.renewal_due) queue.push({ id: 'crl', tone: 'warn', icon: 'revocation', count: 1, title: `CRL ${crl.latest_crl_number} is due for renewal`, detail: crl.next_update ? `Next update before ${new Date(crl.next_update).toLocaleString()}.` : 'Publish the next CRL.', action: isOfficer ? 'Publish CRL' : 'Open CRLs', section: 'revocation' });
  }
  if (isReader && health.expiringSoon) queue.push({ id: 'expiring', tone: 'warn', icon: 'certificate', count: health.expiringSoon, title: 'Certificates expiring within 30 days', detail: 'Plan their renewal before the recorded notAfter date.', action: 'View certificates', section: 'certificates' });
  if (isReader && attention.reconciliation) queue.push({ id: 'recon', tone: 'bad', icon: 'key', count: attention.reconciliation, title: 'Signing results to reconcile', detail: 'A signing outcome was ambiguous in the last 7 days; reconcile before signing again.', action: 'Open audit trail', section: 'audit' });
  if (isReader && attention.denied) queue.push({ id: 'denied', tone: 'info', icon: 'alert', count: attention.denied, title: 'Denied operations in the last 7 days', detail: 'Check whether they were expected.', action: 'Open audit trail', section: 'audit' });
  const loadingQueue = pending > 0;

  return <section className="ui-dash" aria-label={`${ca.display_name} at a glance`}>
    <div className="ui-dash-head">
      <div><span className="ui-eyebrow">Selected authority</span><h2>{ca.display_name}</h2></div>
      {ca.operational_state && <StatusBadge status={ca.operational_state} />}
    </div>

    <div className="ui-dash-grid">
      <div className="ui-panel ui-queue">
        <div className="ui-panel-head"><h3>Needs attention</h3>{!loadingQueue && <span className="ui-count">{queue.length}</span>}</div>
        {loadingQueue && queue.length === 0 ? <div className="ui-skeleton">{[0, 1, 2].map(row => <div key={row} className="ui-skeleton-row" />)}</div>
          : queue.length === 0 ? <div className="ui-all-clear"><span className="ui-all-clear-icon"><Icon name="check" size={22} /></span><strong>All clear</strong><p>Nothing in your roles waits on you for this authority.</p></div>
            : <ul className="ui-queue-list">{queue.map(item => <li key={item.id} className={`ui-queue-item ui-tone-${item.tone}`}>
              <span className="ui-queue-icon"><Icon name={item.icon} size={18} /></span>
              <div className="ui-queue-text"><strong>{item.title}</strong><span>{item.detail}</span></div>
              <span className="ui-queue-count" aria-label={`${item.count} items`}>{item.count}</span>
              <button type="button" className="ui-button ui-button-secondary ui-button-sm" onClick={() => onNavigate(item.section)}>{item.action}<Icon name="chevron" size={14} /></button>
            </li>)}</ul>}
      </div>

      {isReader && <div className="ui-kpis">
        <Kpi label="Valid certificates" value={health.valid} tone="good" hint="Within their recorded period" onClick={() => onNavigate('certificates')} />
        <Kpi label="Expiring ≤ 30 days" value={health.expiringSoon} tone={health.expiringSoon ? 'warn' : 'neutral'} hint="Recorded notAfter soon" onClick={() => onNavigate('certificates')} />
        <Kpi label="Period ended" value={health.expired} tone={health.expired ? 'bad' : 'neutral'} hint="Recorded notAfter passed" onClick={() => onNavigate('certificates')} />
        <Kpi label="Events, 14 days" value={events14} tone="info" hint={denied14 ? `${denied14} denied` : 'No denial'} onClick={() => onNavigate('audit')} />
      </div>}
    </div>

    {isReader && <div className="ui-chart-grid">
      <div className="ui-panel">
        <div className="ui-panel-head"><h3>Upcoming expiries</h3><span className="ui-panel-note">Next 12 weeks{certificatesComplete ? '' : ' · loaded certificates'}</span></div>
        <BarChart buckets={expiries} label={bucket => new Date(bucket.start).toLocaleDateString(undefined, { day: 'numeric', month: 'short' })}
          tooltip={bucket => `${bucket.count} certificate${bucket.count === 1 ? '' : 's'} · week of ${new Date(bucket.start).toLocaleDateString()}`}
          summary={`${expiries.reduce((sum, bucket) => sum + bucket.count, 0)} certificates expire in the next 12 weeks`} empty="No recorded expiry in the next 12 weeks." />
      </div>
      <div className="ui-panel">
        <div className="ui-panel-head"><h3>Audit activity</h3><span className="ui-panel-note">Events per day, last 14 days{auditComplete ? '' : ' · loaded events'}</span></div>
        <BarChart buckets={activity} label={bucket => new Date(bucket.start).toLocaleDateString(undefined, { day: 'numeric', month: 'short', timeZone: 'UTC' })}
          tooltip={bucket => `${bucket.count} event${bucket.count === 1 ? '' : 's'}${bucket.extra ? ` · ${bucket.extra} denied` : ''} · ${new Date(bucket.start).toLocaleDateString(undefined, { timeZone: 'UTC' })}`}
          summary={`${events14} audit events in the last 14 days, ${denied14} denied`} empty="No audit event in the last 14 days." />
      </div>
    </div>}
  </section>;
}

function Kpi({ label, value, tone, hint, onClick }: { label: string; value: number; tone: 'good' | 'warn' | 'bad' | 'info' | 'neutral'; hint: string; onClick: () => void }) {
  return <button type="button" className={`ui-kpi ui-tone-${tone}`} onClick={onClick}>
    <span className="ui-kpi-label"><span className="ui-badge-dot" aria-hidden="true" />{label}</span>
    <strong>{value.toLocaleString()}</strong>
    <small>{hint}</small>
  </button>;
}

/** A single-series bar chart with a hover tooltip and a table for screen readers. */
function BarChart({ buckets, label, tooltip, summary, empty }: { buckets: Bucket[]; label: (bucket: Bucket) => string; tooltip: (bucket: Bucket) => string; summary: string; empty: string }) {
  const [hover, setHover] = useState<number | null>(null);
  const max = Math.max(1, ...buckets.map(bucket => bucket.count));
  const total = buckets.reduce((sum, bucket) => sum + bucket.count, 0);
  const width = 100 / buckets.length;
  const ticks = [0, Math.floor(buckets.length / 2), buckets.length - 1];
  return <div className="ui-chart">
    {total === 0 && <p className="ui-chart-empty">{empty}</p>}
    <div className="ui-chart-plot" role="img" aria-label={summary} onMouseLeave={() => setHover(null)}>
      <div className="ui-chart-grid-line" style={{ bottom: '100%' }}><span>{max}</span></div>
      <div className="ui-chart-grid-line" style={{ bottom: '50%' }}><span>{max > 1 ? Math.round(max / 2) : ''}</span></div>
      {buckets.map((bucket, index) => <div key={bucket.key} className={hover === index ? 'ui-bar-slot hover' : 'ui-bar-slot'} style={{ left: `${index * width}%`, width: `${width}%` }}
        onMouseEnter={() => setHover(index)}>
        <div className="ui-bar" style={{ height: bucket.count ? `max(4px, ${(bucket.count / max) * 100}%)` : 0 }} />
      </div>)}
      {hover !== null && total > 0 && <div className="ui-chart-tip" style={{ left: `${Math.min(80, Math.max(20, (hover + 0.5) * width))}%` }}>{tooltip(buckets[hover])}</div>}
    </div>
    <div className="ui-chart-axis">{ticks.map(index => <span key={index} style={{ left: `${(index + 0.5) * width}%` }}>{label(buckets[index])}</span>)}</div>
    <table className="sr-only"><caption>{summary}</caption><tbody>{buckets.map(bucket => <tr key={bucket.key}><th scope="row">{label(bucket)}</th><td>{bucket.count}</td></tr>)}</tbody></table>
  </div>;
}
