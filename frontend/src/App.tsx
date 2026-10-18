import { useEffect, useMemo, useRef, useState } from 'react';
import type { User } from 'oidc-client-ts';
import { ApiError, apiGetPage, type AuditEvent, type Certificate, type CertificateAuthority } from './api';
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
  const [caCursor, setCaCursor] = useState<string | null>(null);
  const [caMoreLoading, setCaMoreLoading] = useState(false);
  const [caMoreError, setCaMoreError] = useState<string | null>(null);
  const caKey = useRef('');
  const caMoreController = useRef<AbortController | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [certificateError, setCertificateError] = useState<string | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [dataError, setDataError] = useState<string | null>(null);
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [selectedCertificate, setSelectedCertificate] = useState<Certificate | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [selectedAuditEvent, setSelectedAuditEvent] = useState<AuditEvent | null>(null);
  const [certificateCursor, setCertificateCursor] = useState<string | null>(null);
  const [auditCursor, setAuditCursor] = useState<string | null>(null);
  const [moreLoading, setMoreLoading] = useState(false);
  const [certificateMoreError, setCertificateMoreError] = useState<string | null>(null);
  const [auditMoreError, setAuditMoreError] = useState<string | null>(null);
  const detailKey = useRef('');
  const moreController = useRef<AbortController | null>(null);
  const [reload, setReload] = useState(0);

  const clearSession = () => {
    setUser(null);
    setCas([]);
    setSelectedCaId(null);
    setCertificates([]);
    setSelectedCertificate(null);
    setAuditEvents([]);
    setSelectedAuditEvent(null);
  };

  const rejectSession = () => {
    clearSession();
    setSessionError('Your session is no longer valid. Sign in again.');
    void userManager?.removeUser().catch(() => {});
  };

  const handleReadError = (error: unknown, fallback: string, show: (message: string) => void) => {
    if (error instanceof ApiError && error.status === 401) {
      rejectSession();
      return;
    }
    show(error instanceof Error ? error.message : fallback);
  };

  useEffect(() => {
    let cancelled = false;
    const removeExpired = userManager?.events.addAccessTokenExpired(() => {
      if (!cancelled) {
        clearSession();
        setSessionError('Your session has expired. Sign in again.');
      }
    });
    const removeUnloaded = userManager?.events.addUserUnloaded(() => {
      if (!cancelled) clearSession();
    });
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
    return () => {
      cancelled = true;
      removeExpired?.();
      removeUnloaded?.();
    };
  }, []);

  useEffect(() => {
    if (!user || user.expired) return;
    caKey.current = `${user.access_token}/${reload}`;
    caMoreController.current?.abort();
    setCaMoreLoading(false);
    setCaMoreError(null);
    setCaCursor(null);
    const controller = new AbortController();
    setCasLoading(true);
    setDataError(null);
    apiGetPage<CertificateAuthority>('/v1/cas', user.access_token, controller.signal)
      .then(page => {
        setCas(page.items);
        setCaCursor(page.nextCursor);
        setSelectedCaId(current => page.items.some(ca => ca.ca_id === current) ? current : page.items[0]?.ca_id ?? null);
      })
      .catch(error => { if (!controller.signal.aborted) handleReadError(error, 'Could not load authorities.', setDataError); })
      .finally(() => { if (!controller.signal.aborted) setCasLoading(false); });
    return () => { controller.abort(); caMoreController.current?.abort(); };
  }, [user, reload]);

  async function loadMoreCas() {
    if (!user || user.expired || !caCursor || casLoading || caMoreLoading) return;
    const key = caKey.current;
    const controller = new AbortController();
    caMoreController.current = controller;
    setCaMoreLoading(true);
    setCaMoreError(null);
    try {
      const page = await apiGetPage<CertificateAuthority>(`/v1/cas?after=${encodeURIComponent(caCursor)}`, user.access_token, controller.signal);
      if (caKey.current === key) {
        setCas(current => [...current, ...page.items]);
        setCaCursor(page.nextCursor);
      }
    } catch (error) {
      if (!controller.signal.aborted && caKey.current === key) handleReadError(error, 'Could not load more authorities.', setCaMoreError);
    } finally {
      if (caKey.current === key) setCaMoreLoading(false);
    }
  }

  useEffect(() => {
    detailKey.current = `${selectedCaId ?? ''}/${reload}`;
    moreController.current?.abort();
    setMoreLoading(false);
    setCertificateMoreError(null);
    setAuditMoreError(null);
    setDetailLoading(false);
    setCertificateCursor(null);
    setAuditCursor(null);
    setCertificates([]);
    setAuditEvents([]);
    setCertificateError(null);
    setAuditError(null);
    if (!user || user.expired || !selectedCaId) {
      return;
    }
    const controller = new AbortController();
    setDetailLoading(true);
    setDataError(null);
    const base = `/v1/cas/${encodeURIComponent(selectedCaId)}`;
    Promise.allSettled([
      apiGetPage<Certificate>(`${base}/certificates`, user.access_token, controller.signal),
      apiGetPage<AuditEvent>(`${base}/audit`, user.access_token, controller.signal),
    ]).then(([certs, events]) => {
      if (controller.signal.aborted) return;
      if ([certs, events].some(result => result.status === 'rejected' && result.reason instanceof ApiError && result.reason.status === 401)) {
        rejectSession();
        return;
      }
      if (certs.status === 'fulfilled') {
        setCertificates(certs.value.items);
        setCertificateCursor(certs.value.nextCursor);
      } else {
        setCertificateError(certs.reason instanceof Error ? certs.reason.message : 'Could not load certificates.');
      }
      if (events.status === 'fulfilled') {
        setAuditEvents(events.value.items);
        setAuditCursor(events.value.nextCursor);
      } else {
        setAuditError(events.reason instanceof Error ? events.reason.message : 'Could not load audit events.');
      }
    }).finally(() => { if (!controller.signal.aborted) setDetailLoading(false); });
    return () => { controller.abort(); moreController.current?.abort(); };
  }, [user, selectedCaId, reload]);

  async function loadOlder(kind: 'certificates' | 'audit') {
    const cursor = kind === 'certificates' ? certificateCursor : auditCursor;
    if (!user || user.expired || !selectedCaId || !cursor || detailLoading || moreLoading) return;
    const key = detailKey.current;
    const controller = new AbortController();
    moreController.current = controller;
    setMoreLoading(true);
    if (kind === 'certificates') setCertificateMoreError(null);
    else setAuditMoreError(null);
    try {
      const path = `/v1/cas/${encodeURIComponent(selectedCaId)}/${kind}?before=${encodeURIComponent(cursor)}`;
      if (kind === 'certificates') {
        const page = await apiGetPage<Certificate>(path, user.access_token, controller.signal);
        if (detailKey.current === key) {
          setCertificates(current => [...current, ...page.items]);
          setCertificateCursor(page.nextCursor);
        }
      } else {
        const page = await apiGetPage<AuditEvent>(path, user.access_token, controller.signal);
        if (detailKey.current === key) {
          setAuditEvents(current => [...current, ...page.items]);
          setAuditCursor(page.nextCursor);
        }
      }
    } catch (error) {
      if (!controller.signal.aborted && detailKey.current === key) {
        handleReadError(error, 'Could not load older records.', kind === 'certificates' ? setCertificateMoreError : setAuditMoreError);
      }
    } finally {
      if (detailKey.current === key) setMoreLoading(false);
    }
  }

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
        <button className={section === 'authorities' ? 'active' : ''} onClick={() => setSection('authorities')}><span>◇</span> Authorities <small>{cas.length}{caCursor ? '+' : ''}</small></button>
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
            <div className="metric-grid"><Metric label="AUTHORITIES IN SCOPE" value={`${cas.length}${caCursor ? '+' : ''}`} detail="Authorities loaded" icon="◇" /><Metric label="SELECTED CA CERTIFICATES" value={detailLoading ? '…' : certificateError ? '—' : String(certificates.length)} detail="Records loaded" icon="▤" /><Metric label="RECENT AUDIT EVENTS" value={detailLoading ? '…' : auditError ? '—' : String(auditEvents.length)} detail="Records loaded" icon="◷" /></div>
            <div className="section-head"><div><h2>Your authorities</h2><p>Choose an authority to inspect its records.</p></div><button className="link-button" onClick={() => setSection('authorities')}>View all authorities →</button></div>
            <AuthorityList cas={cas} selectedCaId={selectedCaId} onSelect={id => { setSelectedCaId(id); setSection('authorities'); }} />
            {caCursor && (caMoreError ? <LoadFailure message={caMoreError} onRetry={() => void loadMoreCas()} /> : <button className="link-button pagination-action" disabled={caMoreLoading} onClick={() => void loadMoreCas()}>{caMoreLoading ? 'Loading…' : 'Load more authorities'}</button>)}
          </>}
          {section !== 'overview' && <div className="workspace-grid"><div className="authority-panel"><div className="panel-heading"><span>AUTHORITIES LOADED</span><span>{cas.length}{caCursor ? '+' : ''}</span></div><AuthorityList cas={cas} selectedCaId={selectedCaId} onSelect={setSelectedCaId} compact />{caCursor && (caMoreError ? <LoadFailure message={caMoreError} onRetry={() => void loadMoreCas()} /> : <button className="link-button pagination-action" disabled={caMoreLoading} onClick={() => void loadMoreCas()}>{caMoreLoading ? 'Loading…' : 'Load more authorities'}</button>)}</div><div className="detail-panel">
            {selectedCa && <><div className="detail-header"><div><div className="eyebrow">CERTIFICATE AUTHORITY</div><h2>{selectedCa.display_name}</h2><span className="mono muted">{selectedCa.ca_id}</span></div><span className="state-pill"><span className="status-dot" /> LAB RECORD</span></div>
              {section === 'authorities' && <div className="detail-content"><div className="detail-grid"><Info label="POLICY VERSION" value={selectedCa.policy_version} /><Info label="CREATED" value={displayDate(selectedCa.created_at)} /><Info label="PARENT AUTHORITY" value={selectedCa.parent_ca_id ? shortId(selectedCa.parent_ca_id) : 'Root / not recorded'} /><Info label="AUTHORITY ID" value={shortId(selectedCa.ca_id)} /></div><div className="subtle-panel"><b>About this record</b><p>This console shows database metadata. It does not assert that a public CA certificate, signing key or policy publication has been independently verified.</p></div><div className="quick-links"><button onClick={() => setSection('certificates')}>View certificates →</button><button onClick={() => setSection('audit')}>View audit trail →</button></div></div>}
              {section === 'certificates' && <div className="detail-content"><div className="table-heading"><h3>Certificates</h3><span>{certificates.length} records loaded</span></div>{detailLoading ? <LoadingRows /> : certificateError ? <LoadFailure message={certificateError} onRetry={() => setReload(value => value + 1)} /> : certificates.length === 0 ? <EmptyDetail title="No certificates recorded" detail="This authority has no issued certificate metadata in the laboratory database." /> : <><div className="table-wrap"><table><thead><tr><th>SERIAL</th><th>STATE</th><th>SIGNED</th><th>FINGERPRINT SHA-256</th></tr></thead><tbody>{certificates.map(cert => <tr key={cert.request_id}><td className="mono"><button className="record-link" onClick={() => setSelectedCertificate(cert)} aria-label={`View certificate ${cert.serial_hex}`}>{shortId(cert.serial_hex)}</button></td><td><span className="row-state">{cert.state}</span></td><td>{displayDate(cert.signed_at)}</td><td className="mono" title={cert.fingerprint_sha256}>{shortId(cert.fingerprint_sha256)}</td></tr>)}</tbody></table></div>{certificateCursor && (certificateMoreError ? <LoadFailure message={certificateMoreError} onRetry={() => void loadOlder('certificates')} /> : <button className="link-button pagination-action" disabled={moreLoading} onClick={() => void loadOlder('certificates')}>{moreLoading ? 'Loading…' : 'Load older certificates'}</button>)}</>}</div>}
              {section === 'audit' && <div className="detail-content"><div className="table-heading"><h3>Recent events</h3><span>{auditEvents.length} records loaded</span></div>{detailLoading ? <LoadingRows /> : auditError ? <LoadFailure message={auditError} onRetry={() => setReload(value => value + 1)} /> : auditEvents.length === 0 ? <EmptyDetail title="No audit events recorded" detail="No events are available for this authority in the laboratory database." /> : <><div className="timeline">{auditEvents.map(event => <div className="timeline-item" key={event.event_id}><span className="timeline-dot" /><div><button className="record-link" onClick={() => setSelectedAuditEvent(event)} aria-label={`View audit event ${event.event_id}`}>{event.event_type}</button><p>{event.decision}</p><small>{displayDate(event.recorded_at)} · Policy {event.policy_version ?? 'not recorded'}</small></div></div>)}</div>{auditCursor && (auditMoreError ? <LoadFailure message={auditMoreError} onRetry={() => void loadOlder('audit')} /> : <button className="link-button pagination-action" disabled={moreLoading} onClick={() => void loadOlder('audit')}>{moreLoading ? 'Loading…' : 'Load older audit events'}</button>)}</>}</div>}
            </>}
          </div></div>}
        </>}
      </main>
      {selectedCertificate?.ca_id === selectedCaId && section === 'certificates' && certificates.some(cert => cert.request_id === selectedCertificate.request_id) && <CertificateDialog certificate={selectedCertificate} onClose={() => setSelectedCertificate(null)} />}
      {selectedAuditEvent?.ca_id === selectedCaId && section === 'audit' && auditEvents.some(event => event.event_id === selectedAuditEvent.event_id) && <AuditDialog event={selectedAuditEvent} onClose={() => setSelectedAuditEvent(null)} />}
    </div>
  </div>;
}

function CertificateDialog({ certificate, onClose }: { certificate: Certificate; onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    return () => element?.close();
  }, []);
  return <dialog ref={dialog} className="certificate-dialog" aria-labelledby="certificate-dialog-title" onClose={onClose}>
    <div className="dialog-heading"><div><div className="eyebrow">CERTIFICATE METADATA</div><h2 id="certificate-dialog-title">Certificate detail</h2></div><button className="dialog-close" aria-label="Close certificate detail" onClick={() => dialog.current?.close()}>×</button></div>
    <div className="detail-grid"><Info label="SERIAL" value={certificate.serial_hex} /><Info label="FINGERPRINT SHA-256" value={certificate.fingerprint_sha256} /><Info label="REQUEST ID" value={certificate.request_id} /><Info label="STATE" value={certificate.state} /><Info label="SIGNED" value={displayDate(certificate.signed_at)} /><Info label="PUBLISHED" value={displayDate(certificate.published_at)} /></div>
    <p className="dialog-note">Database metadata only. Certificate contents and cryptographic validity are not shown or verified here.</p>
  </dialog>;
}

function AuditDialog({ event, onClose }: { event: AuditEvent; onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    return () => element?.close();
  }, []);
  return <dialog ref={dialog} className="certificate-dialog" aria-labelledby="audit-dialog-title" onClose={onClose}>
    <div className="dialog-heading"><div><div className="eyebrow">AUDIT METADATA</div><h2 id="audit-dialog-title">Audit event detail</h2></div><button className="dialog-close" aria-label="Close audit event detail" onClick={() => dialog.current?.close()}>×</button></div>
    <div className="detail-grid"><Info label="EVENT ID" value={event.event_id} /><Info label="EVENT TYPE" value={event.event_type} /><Info label="DECISION" value={event.decision} /><Info label="POLICY VERSION" value={event.policy_version ?? 'Not recorded'} /><Info label="RECORDED" value={displayDate(event.recorded_at)} /></div>
    <p className="dialog-note">Database metadata only. This view does not include actor identity or independent audit integrity proof.</p>
  </dialog>;
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
function LoadFailure({ message, onRetry }: { message: string; onRetry: () => void }) {
  return <div className="notice error" role="alert">{message} <button onClick={onRetry}>Retry</button></div>;
}
function EmptyDetail({ title, detail }: { title: string; detail: string }) { return <div className="empty-detail"><div>□</div><strong>{title}</strong><p>{detail}</p></div>; }
