import { useEffect, useRef, useState } from 'react';
import { ApiError, apiGet, apiPost } from './api';

interface Application {
  application_id: string;
  ca_id: string;
  profile_id: string;
  revision: number;
  csr_sha256: string;
  subject_cn: string;
  dns_names: string[];
  validity_days: number;
  status: 'SUBMITTED' | 'APPROVED' | 'REJECTED' | 'ISSUING' | 'ISSUED' | 'RECONCILIATION_REQUIRED'
    | 'REVOCATION_REQUESTED' | 'REVOKED';
  decision_reason: string | null;
  submitted_at: string;
  decided_at: string | null;
  certificate_serial_hex: string | null;
  certificate_sha256: string | null;
  open_revocation_id: string | null;
  open_revocation_reason_code: number | null;
  revocation_reason_code: number | null;
  revoked_at: string | null;
}

interface PublishedCrl {
  crl_number: number;
  this_update: string;
  next_update: string;
  crl_sha256: string;
  published_at: string;
  entry_count: number;
}

interface CrlPublication {
  status: 'PUBLISHED' | 'RECONCILIATION_REQUIRED';
  crl_number: number;
  crl_pem: string | null;
}

// RFC 5280 reasons the laboratory accepts for end-entity certificates.
const REASONS: [number, string][] = [
  [0, 'Unspecified'], [1, 'Key compromise'], [3, 'Affiliation changed'], [4, 'Superseded'],
  [5, 'Cessation of operation'], [9, 'Privilege withdrawn'],
];
const reasonName = (code: number | null) => REASONS.find(([value]) => value === code)?.[1] ?? String(code);

interface Issuance {
  status: 'ISSUED' | 'RECONCILIATION_REQUIRED';
  certificate_pem: string | null;
  serial_hex: string | null;
}

interface Props {
  caId: string;
  token: string;
  canRequest: boolean;
  canDecide: boolean;
  onUnauthorized: () => void;
}

function message(failure: unknown): string {
  if (failure instanceof ApiError) {
    if (failure.status === 403) return 'Your role or grant does not allow this, or you cannot decide on your own application.';
    if (failure.status === 404) return 'The profile has no active revision for this authority.';
    if (failure.status === 409) return 'Conflict: already decided or revoked, a request is already open, an earlier CRL attempt is still unresolved, or the authority or profile revision is no longer active.';
    if (failure.status === 422) return 'Refused: the CSR must be a P-256 PKCS#10 request whose only subject is CN=<common name>, and the names, zones and validity must fit the active profile of an ACTIVE authority.';
    if (failure.status === 502) return 'The signing outcome is uncertain: the request needs reconciliation and will not be signed again.';
    if (failure.status === 503) return 'No laboratory signer is configured for this API.';
    if (failure.status === 400) return 'The request is invalid: lowercase DNS names without wildcards, the common name among them, and a validity in days.';
  }
  return failure instanceof Error ? failure.message : 'The request failed.';
}

/**
 * Certificate applications (ADR-0016). A requester submits a CSR generated
 * outside the browser; a registration officer other than the requester
 * approves or rejects it. An approved application is issued once by the
 * laboratory signer (ADR-0017); the browser only shows the certificate.
 */
export function CertificateApplicationPanel({ caId, token, canRequest, canDecide, onUnauthorized }: Props) {
  const [items, setItems] = useState<Application[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState('');
  const [reload, setReload] = useState(0);
  const [busy, setBusy] = useState(false);
  const [profile, setProfile] = useState('server');
  const [commonName, setCommonName] = useState('');
  const [names, setNames] = useState('');
  const [days, setDays] = useState('30');
  const [pem, setPem] = useState('');
  const [reason, setReason] = useState<Record<string, string>>({});
  const [issued, setIssued] = useState<{ subject: string; pem: string; serial: string } | null>(null);
  const [revocationCode, setRevocationCode] = useState<Record<string, number>>({});
  const [crls, setCrls] = useState<PublishedCrl[] | null>(null);
  const [crl, setCrl] = useState<{ number: number; pem: string } | null>(null);
  const key = useRef(crypto.randomUUID());
  const base = `/v1/cas/${encodeURIComponent(caId)}/certificate-applications`;

  useEffect(() => {
    const controller = new AbortController();
    apiGet<Application[]>(base, token, controller.signal)
      .then(rows => { setItems(rows); setError(null); })
      .catch(failure => {
        if (controller.signal.aborted) return;
        if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
        else setError(failure instanceof Error ? failure.message : 'Could not load certificate applications.');
      });
    return () => controller.abort();
  }, [base, token, reload]);

  async function write(path: string, body: unknown, done: string) {
    setBusy(true);
    setError(null);
    try {
      await apiPost(path, token, body, key.current);
      key.current = crypto.randomUUID();
      setNotice(done);
      setReload(value => value + 1);
    } catch (failure) {
      key.current = crypto.randomUUID();
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
      else setError(message(failure));
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    const controller = new AbortController();
    apiGet<PublishedCrl[]>(`/v1/cas/${encodeURIComponent(caId)}/crls`, token, controller.signal)
      .then(rows => setCrls(rows))
      .catch(() => { if (!controller.signal.aborted) setCrls(null); });
    return () => controller.abort();
  }, [caId, token, reload]);

  async function publishCrl() {
    setBusy(true);
    setError(null);
    try {
      const result = await apiPost<CrlPublication>(`/v1/cas/${encodeURIComponent(caId)}/crls`, token, {}, key.current);
      key.current = crypto.randomUUID();
      if (result.value.crl_pem) setCrl({ number: result.value.crl_number, pem: result.value.crl_pem });
      setNotice(`CRL ${result.value.crl_number} published.`);
    } catch (failure) {
      key.current = crypto.randomUUID();
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
      else setError(message(failure));
    } finally {
      setReload(value => value + 1);
      setBusy(false);
    }
  }

  async function issue(item: Application) {
    setBusy(true);
    setError(null);
    try {
      const result = await apiPost<Issuance>(`${base}/${item.application_id}/issuance`, token, {}, key.current);
      key.current = crypto.randomUUID();
      if (result.value.certificate_pem && result.value.serial_hex) {
        setIssued({ subject: item.subject_cn, pem: result.value.certificate_pem, serial: result.value.serial_hex });
      }
      setNotice(result.status === 201 ? `Certificate for ${item.subject_cn} issued.` : `The certificate for ${item.subject_cn} was already issued.`);
      setReload(value => value + 1);
    } catch (failure) {
      key.current = crypto.randomUUID();
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
      else setError(message(failure));
      setReload(value => value + 1);
    } finally {
      setBusy(false);
    }
  }

  const dnsNames = names.split(/[\s,]+/u).filter(Boolean);
  return <section className="panel certificate-applications" aria-labelledby="certificate-applications-title">
    <div className="panel-header"><h2 id="certificate-applications-title">Certificate applications</h2></div>
    <p>Applications are checked against the authority's active profile revision and approved by a registration officer. Approved applications are signed once by the laboratory signer, a software key with no custody or hardware protection. Issued certificates are revoked when a registration officer approves a request, and appear on the next CRL an officer publishes.</p>
    {notice && <p role="status">{notice}</p>}
    {canDecide && <div className="form-actions">
      <button type="button" disabled={busy} onClick={() => void publishCrl()}>Publish CRL</button>
    </div>}
    {crl && <div className="subtle-panel">
      <h3>CRL {crl.number}</h3>
      <p><small>Verify it with <code>openssl crl -in crl.pem -CAfile root.crt -noout -verify</code>, and a certificate against it with <code>openssl verify -crl_check -CAfile root.crt -CRLfile crl.pem cert.pem</code>.</small></p>
      <label className="form-field"><span>CRL (PEM)</span><textarea rows={8} readOnly value={crl.pem} spellCheck={false} /></label>
    </div>}
    {crls && crls.length > 0 && <table className="data-table" aria-label="Published CRLs">
      <thead><tr><th>CRL number</th><th>Entries</th><th>This update</th><th>Next update</th></tr></thead>
      <tbody>{crls.map(row => <tr key={row.crl_number}>
        <td>{row.crl_number}<br /><small>SHA-256 {row.crl_sha256.slice(0, 16)}…</small></td>
        <td>{row.entry_count}</td><td>{row.this_update}</td><td>{row.next_update}</td>
      </tr>)}</tbody>
    </table>}
    {issued && <div className="subtle-panel">
      <h3>Certificate for {issued.subject}</h3>
      <p><small>Serial {issued.serial}. Verify it against the issuing CA's root, for example <code>openssl verify -CAfile root.crt -purpose sslserver cert.pem</code>.</small></p>
      <label className="form-field"><span>Certificate (PEM)</span><textarea rows={8} readOnly value={issued.pem} spellCheck={false} /></label>
    </div>}
    {error && <div className="notice error" role="alert">{error}</div>}
    {canRequest && <form className="subtle-panel" onSubmit={event => {
      event.preventDefault();
      void write(base, { profile_id: profile, csr_pem: pem, common_name: commonName, dns_names: dnsNames, validity_days: Number(days) },
        `Application for ${commonName} submitted.`);
    }}>
      <label className="form-field"><span>Profile ID</span><input value={profile} onChange={event => setProfile(event.target.value)} /></label>
      <label className="form-field"><span>Common name</span><input value={commonName} onChange={event => setCommonName(event.target.value.trim())} /></label>
      <label className="form-field"><span>DNS names (comma or space separated)</span><input value={names} onChange={event => setNames(event.target.value)} /></label>
      <label className="form-field"><span>Validity (days)</span><input inputMode="numeric" value={days} onChange={event => setDays(event.target.value)} /></label>
      <label className="form-field"><span>CSR (PEM)</span><textarea rows={5} value={pem} onChange={event => setPem(event.target.value)} spellCheck={false} /></label>
      <p><small>Generate the key and CSR outside the browser, for example: <code>openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout key.pem -subj "/CN={commonName || 'www.lab.invalid'}"</code>. Never paste a private key.</small></p>
      <button type="submit" disabled={busy || !commonName || dnsNames.length === 0 || !pem.trim()}>{busy ? 'Submitting…' : 'Submit application'}</button>
    </form>}
    {items && items.length === 0 && <p>No certificate applications for this authority.</p>}
    {items && items.length > 0 && <table className="data-table" aria-label="Certificate applications">
      <thead><tr><th>Common name</th><th>Status</th><th>Profile</th><th>Names</th></tr></thead>
      <tbody>{items.map(item => <tr key={item.application_id}>
        <td><b>{item.subject_cn}</b><br /><small>CSR SHA-256 {item.csr_sha256.slice(0, 16)}…</small></td>
        <td><span className="status-pill">{item.status}</span>{item.decision_reason && <><br /><small>{item.decision_reason}</small></>}
          {item.certificate_serial_hex && <><br /><small>Serial {item.certificate_serial_hex}</small></>}
          {item.status === 'APPROVED' && <div className="form-actions">
            <button type="button" disabled={busy} onClick={() => void issue(item)}>Issue certificate</button>
          </div>}
          {item.revoked_at && <><br /><small>Revoked {item.revoked_at} ({reasonName(item.revocation_reason_code)})</small></>}
          {item.status === 'REVOCATION_REQUESTED' && <><br /><small>Revocation requested ({reasonName(item.open_revocation_reason_code)})</small></>}
          {item.status === 'ISSUED' && <div className="form-actions">
            <select aria-label={`Revocation reason for ${item.subject_cn}`} value={revocationCode[item.application_id] ?? 1}
              onChange={event => setRevocationCode(values => ({ ...values, [item.application_id]: Number(event.target.value) }))}>
              {REASONS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select>
            <input aria-label={`Revocation explanation for ${item.subject_cn}`} value={reason[item.application_id] ?? ''}
              onChange={event => setReason(values => ({ ...values, [item.application_id]: event.target.value }))} />
            <button type="button" disabled={busy || !(reason[item.application_id] ?? '').trim()}
              onClick={() => void write(`${base}/${item.application_id}/revocation-requests`,
                { reason_code: revocationCode[item.application_id] ?? 1, reason: (reason[item.application_id] ?? '').trim() },
                `Revocation of ${item.subject_cn} requested.`)}>Request revocation</button>
          </div>}
          {canDecide && item.status === 'REVOCATION_REQUESTED' && item.open_revocation_id && <div className="form-actions">
            <input aria-label={`Revocation decision reason for ${item.subject_cn}`} value={reason[item.application_id] ?? ''}
              onChange={event => setReason(values => ({ ...values, [item.application_id]: event.target.value }))} />
            <button type="button" disabled={busy || !(reason[item.application_id] ?? '').trim()}
              onClick={() => void write(`${base}/${item.application_id}/revocation-requests/${item.open_revocation_id}/decision`,
                { decision: 'approve', reason: (reason[item.application_id] ?? '').trim() }, `${item.subject_cn} revoked.`)}>Approve revocation</button>
            <button type="button" className="link-button" disabled={busy || !(reason[item.application_id] ?? '').trim()}
              onClick={() => void write(`${base}/${item.application_id}/revocation-requests/${item.open_revocation_id}/decision`,
                { decision: 'reject', reason: (reason[item.application_id] ?? '').trim() }, `Revocation of ${item.subject_cn} rejected.`)}>Reject revocation</button>
          </div>}
        </td>
        <td>{item.profile_id} r{item.revision}<br /><small>{item.validity_days} days</small></td>
        <td>{item.dns_names.join(', ')}
          {canDecide && item.status === 'SUBMITTED' && <div className="form-actions">
            <input aria-label={`Decision reason for ${item.subject_cn}`} value={reason[item.application_id] ?? ''}
              onChange={event => setReason(values => ({ ...values, [item.application_id]: event.target.value }))} />
            <button type="button" disabled={busy || !(reason[item.application_id] ?? '').trim()}
              onClick={() => void write(`${base}/${item.application_id}/decision`, { decision: 'approve', reason: (reason[item.application_id] ?? '').trim() }, `Application for ${item.subject_cn} approved.`)}>Approve application</button>
            <button type="button" className="link-button" disabled={busy || !(reason[item.application_id] ?? '').trim()}
              onClick={() => void write(`${base}/${item.application_id}/decision`, { decision: 'reject', reason: (reason[item.application_id] ?? '').trim() }, `Application for ${item.subject_cn} rejected.`)}>Reject application</button>
          </div>}
        </td>
      </tr>)}</tbody>
    </table>}
  </section>;
}
