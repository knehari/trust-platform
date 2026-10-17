import { useEffect, useMemo, useState } from 'react';
import type { User } from 'oidc-client-ts';
import { apiGet, type AuditEvent, type Certificate, type CertificateAuthority } from './api';
import { oidcConfigurationError, userManager } from './oidc';

type Section = 'overview' | 'authorities' | 'certificates' | 'audit';

function displayDate(value: string | null): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}

function shortId(value: string): string {
  return `${value.slice(0, 8)}…${value.slice(-4)}`;
}

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [sessionLoading, setSessionLoading] = useState(true);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [cas, setCas] = useState<CertificateAuthority[]>([]);
  const [selectedCaId, setSelectedCaId] = useState<string | null>(null);
  const [section, setSection] = useState<Section>('overview');
  const [casLoading, setCasLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [dataError, setDataError] = useState<string | null>(null);
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [reload, setReload] = useState(0);

  useEffect(() => {
    let cancelled = false;
    async function restoreSession() {
      if (!userManager) { setSessionLoading(false); return; }
      try {
        const current = window.location.pathname === '/auth/callback'
          ? await userManager.signinRedirectCallback()
          : await userManager.getUser();
        if (window.location.pathname === '/auth/callback') {
          window.history.replaceState({}, '', '/');
        }
        if (!cancelled) setUser(current && !current.expired ? current : null);
      } catch {
        if (!cancelled) setSessionError('Could not complete sign-in. Try again.');
      } finally {
        if (!cancelled) setSessionLoading(false);
      }
    }
    void restoreSession();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!user || user.expired) return;
    const controller = new AbortController();
    setCasLoading(true);
    setDataError(null);
    apiGet<CertificateAuthority[]>('/v1/cas', user.access_token, controller.signal)
      .then(items => {
        setCas(items);
        setSelectedCaId(current => items.some(ca => ca.ca_id === current) ? current : items[0]?.ca_id ?? null);
      })
      .catch(error => { if (!controller.signal.aborted) setDataError(error instanceof Error ? error.message : 'Could not load authorities.'); })
      .finally(() => { if (!controller.signal.aborted) setCasLoading(false); });
    return () => controller.abort();
  }, [user, reload]);

  useEffect(() => {
    if (!user || user.expired || !selectedCaId) {
      setCertificates([]);
      setAuditEvents([]);
      return;
    }
    const controller = new AbortController();
    setDetailLoading(true);
    setDataError(null);
    const base = `/v1/cas/${encodeURIComponent(selectedCaId)}`;
    Promise.all([
      apiGet<Certificate[]>(`${base}/certificates`, user.access_token, controller.signal),
      apiGet<AuditEvent[]>(`${base}/audit`, user.access_token, controller.signal),
    ]).then(([certs, events]) => {
      setCertificates(certs);
      setAuditEvents(events);
    }).catch(error => {
      if (!controller.signal.aborted) setDataError(error instanceof Error ? error.message : 'Could not load CA details.');
    }).finally(() => { if (!controller.signal.aborted) setDetailLoading(false); });
    return () => controller.abort();
  }, [user, selectedCaId, reload]);

  const selectedCa = useMemo(() => cas.find(ca => ca.ca_id === selectedCaId) ?? null, [cas, selectedCaId]);
  const name = user?.profile.preferred_username ?? user?.profile.name ?? user?.profile.sub ?? 'Operator';

  if (sessionLoading) return <div className="center-state"><span className="spinner" /> Establishing secure session…</div>;

  if (oidcConfigurationError || sessionError || !user || user.expired) {
    return <div className="login-layout">
      <div className="login-brand"><div className="brand-mark">S</div><span>SOVEREIGN <b>TRUST</b></span></div>
      <div className="login-card">
        <div className="eyebrow">MANAGEMENT CONSOLE · LABORATORY</div>
        <h1>Clear oversight for every certificate authority.</h1>
        <p>Review CA inventory, certificate metadata and audit activity through a scoped, read-only session.</p>
        {(oidcConfigurationError || sessionError) && <div className="notice error" role="alert">{oidcConfigurationError || sessionError}</div>}
        <button className="primary-button" disabled={!userManager} onClick={() => void userManager?.signinRedirect().catch(() => setSessionError('OIDC sign-in could not start. Check the local test issuer.'))}>
          Sign in with your organization <span aria-hidden="true">↗</span>
        </button>
        <div className="login-footnote">Access is limited to the authorities assigned to your account. No signing keys are available in this console.</div>
      </div>
      <div className="login-footer">PRIVATE LABORATORY SYSTEM · NOT A PRODUCTION TRUST SERVICE</div>
    </div>;
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark">S</div><span>SOVEREIGN<br /><b>TRUST</b></span></div>
      <div className="workspace-tag"><span className="status-dot" /> LAB WORKSPACE</div>
      <nav aria-label="Main navigation" className="nav">
        <div className="nav-label">WORKSPACE</div>
        <button className={section === 'overview' ? 'active' : ''} onClick={() => setSection('overview')}><span>▦</span> Overview</button>
        <button className={section === 'authorities' ? 'active' : ''} onClick={() => setSection('authorities')}><span>◇</span> Authorities <small>{cas.length}</small></button>
        <button className={section === 'certificates' ? 'active' : ''} onClick={() => setSection('certificates')}><span>▤</span> Certificates</button>
        <button className={section === 'audit' ? 'active' : ''} onClick={() => setSection('audit')}><span>◷</span> Audit trail</button>
      </nav>
      <div className="sidebar-bottom"><div className="sidebar-note">Read-only access<br /><span>Changes and issuance are unavailable in this laboratory console.</span></div><div className="version">TRUST PLATFORM · V0.1 LAB</div></div>
    </aside>
    <div className="main-column">
      <header className="topbar"><div className="breadcrumb">Workspace <span>/</span> {section === 'overview' ? 'Overview' : section === 'authorities' ? 'Authorities' : section === 'certificates' ? 'Certificates' : 'Audit trail'}</div><div className="top-actions"><span className="read-badge">READ ONLY</span><button className="icon-button" title="Refresh data" onClick={() => setReload(value => value + 1)}>↻</button><div className="user-avatar" title={name}>{String(name).slice(0, 1).toUpperCase()}</div><button className="text-button" onClick={() => void userManager?.signoutRedirect()}>Sign out</button></div></header>
      <main className="content">
        <div className="page-heading"><div><div className="eyebrow">TRUST OPERATIONS / {section.toUpperCase()}</div><h1>{section === 'overview' ? 'Good to see you.' : section === 'authorities' ? 'Certificate authorities' : section === 'certificates' ? 'Certificate inventory' : 'Audit trail'}</h1><p>{section === 'overview' ? 'A current view of the authorities in your approved scope.' : section === 'authorities' ? 'Inspect policy references and public CA metadata.' : section === 'certificates' ? 'Issued certificate metadata for the selected authority.' : 'Recent recorded events for the selected authority.'}</p></div><div className="page-date">{new Date().toLocaleDateString(undefined, { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}</div></div>
        {dataError && <div className="notice error" role="alert">{dataError} <button onClick={() => setReload(value => value + 1)}>Retry</button></div>}
        {casLoading && <div className="notice loading"><span className="spinner" /> Loading scoped authorities…</div>}
        {!casLoading && cas.length === 0 && !dataError && <div className="empty-state"><div className="empty-icon">◇</div><h2>No authorities in your scope</h2><p>Ask an administrator to grant you the reader role and a CA scope, then refresh this page.</p></div>}
        {cas.length > 0 && <>
          {section === 'overview' && <>
            <div className="metric-grid"><Metric label="AUTHORITIES IN SCOPE" value={String(cas.length)} detail="Available to your session" icon="◇" /><Metric label="SELECTED CA CERTIFICATES" value={detailLoading ? '…' : String(certificates.length)} detail="Latest 100 records" icon="▤" /><Metric label="RECENT AUDIT EVENTS" value={detailLoading ? '…' : String(auditEvents.length)} detail="Latest 100 records" icon="◷" /></div>
            <div className="section-head"><div><h2>Your authorities</h2><p>Choose an authority to inspect its records.</p></div><button className="link-button" onClick={() => setSection('authorities')}>View all authorities →</button></div>
            <AuthorityList cas={cas} selectedCaId={selectedCaId} onSelect={id => { setSelectedCaId(id); setSection('authorities'); }} />
          </>}
          {section !== 'overview' && <div className="workspace-grid"><div className="authority-panel"><div className="panel-heading"><span>AUTHORITIES</span><span>{cas.length}</span></div><AuthorityList cas={cas} selectedCaId={selectedCaId} onSelect={setSelectedCaId} compact /></div><div className="detail-panel">
            {selectedCa && <><div className="detail-header"><div><div className="eyebrow">CERTIFICATE AUTHORITY</div><h2>{selectedCa.display_name}</h2><span className="mono muted">{selectedCa.ca_id}</span></div><span className="state-pill"><span className="status-dot" /> LAB RECORD</span></div>
              {section === 'authorities' && <div className="detail-content"><div className="detail-grid"><Info label="POLICY VERSION" value={selectedCa.policy_version} /><Info label="CREATED" value={displayDate(selectedCa.created_at)} /><Info label="PARENT AUTHORITY" value={selectedCa.parent_ca_id ? shortId(selectedCa.parent_ca_id) : 'Root / not recorded'} /><Info label="AUTHORITY ID" value={shortId(selectedCa.ca_id)} /></div><div className="subtle-panel"><b>About this record</b><p>This console shows database metadata. It does not assert that a public CA certificate, signing key or policy publication has been independently verified.</p></div><div className="quick-links"><button onClick={() => setSection('certificates')}>View certificates →</button><button onClick={() => setSection('audit')}>View audit trail →</button></div></div>}
              {section === 'certificates' && <div className="detail-content"><div className="table-heading"><h3>Certificates</h3><span>Latest 100 records</span></div>{detailLoading ? <LoadingRows /> : certificates.length === 0 ? <EmptyDetail title="No certificates recorded" detail="This authority has no issued certificate metadata in the laboratory database." /> : <div className="table-wrap"><table><thead><tr><th>SERIAL</th><th>STATE</th><th>SIGNED</th><th>FINGERPRINT SHA-256</th></tr></thead><tbody>{certificates.map(cert => <tr key={cert.request_id}><td className="mono">{shortId(cert.serial_hex)}</td><td><span className="row-state">{cert.state}</span></td><td>{displayDate(cert.signed_at)}</td><td className="mono" title={cert.fingerprint_sha256}>{shortId(cert.fingerprint_sha256)}</td></tr>)}</tbody></table></div>}</div>}
              {section === 'audit' && <div className="detail-content"><div className="table-heading"><h3>Recent events</h3><span>Latest 100 records</span></div>{detailLoading ? <LoadingRows /> : auditEvents.length === 0 ? <EmptyDetail title="No audit events recorded" detail="No events are available for this authority in the laboratory database." /> : <div className="timeline">{auditEvents.map(event => <div className="timeline-item" key={event.event_id}><span className="timeline-dot" /><div><strong>{event.event_type}</strong><p>{event.decision}</p><small>{displayDate(event.recorded_at)} · Policy {event.policy_version ?? 'not recorded'}</small></div></div>)}</div>}</div>}
            </>}
          </div></div>}
        </>}
      </main>
    </div>
  </div>;
}

function Metric({ label, value, detail, icon }: { label: string; value: string; detail: string; icon: string }) {
  return <div className="metric"><div className="metric-top"><span>{label}</span><span className="metric-icon">{icon}</span></div><strong>{value}</strong><small>{detail}</small></div>;
}

function AuthorityList({ cas, selectedCaId, onSelect, compact = false }: { cas: CertificateAuthority[]; selectedCaId: string | null; onSelect: (id: string) => void; compact?: boolean }) {
  return <div className={compact ? 'authority-list compact' : 'authority-list'}>{cas.map(ca => <button key={ca.ca_id} className={ca.ca_id === selectedCaId ? 'authority-row selected' : 'authority-row'} onClick={() => onSelect(ca.ca_id)}><span className="ca-emblem">◇</span><span className="ca-text"><strong>{ca.display_name}</strong><small>{shortId(ca.ca_id)} · Policy {ca.policy_version}</small></span><span className="row-arrow">→</span></button>)}</div>;
}

function Info({ label, value }: { label: string; value: string }) {
  return <div className="info-cell"><span>{label}</span><strong>{value}</strong></div>;
}

function LoadingRows() { return <div className="loading-detail"><span className="spinner" /> Loading records…</div>; }
function EmptyDetail({ title, detail }: { title: string; detail: string }) { return <div className="empty-detail"><div>□</div><strong>{title}</strong><p>{detail}</p></div>; }
