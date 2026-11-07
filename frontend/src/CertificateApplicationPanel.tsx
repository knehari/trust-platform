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
  status: 'SUBMITTED' | 'APPROVED' | 'REJECTED';
  decision_reason: string | null;
  submitted_at: string;
  decided_at: string | null;
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
    if (failure.status === 409) return 'The application was already decided, or the authority or profile revision is no longer active.';
    if (failure.status === 422) return 'Refused: the CSR must be a P-256 PKCS#10 request whose only subject is CN=<common name>, and the names, zones and validity must fit the active profile of an ACTIVE authority.';
    if (failure.status === 400) return 'The request is invalid: lowercase DNS names without wildcards, the common name among them, and a validity in days.';
  }
  return failure instanceof Error ? failure.message : 'The request failed.';
}

/**
 * Certificate applications (ADR-0016). A requester submits a CSR generated
 * outside the browser; a registration officer other than the requester
 * approves or rejects it. Nothing is signed yet: issuance is a later slice.
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

  const dnsNames = names.split(/[\s,]+/u).filter(Boolean);
  return <section className="panel certificate-applications" aria-labelledby="certificate-applications-title">
    <div className="panel-header"><h2 id="certificate-applications-title">Certificate applications</h2></div>
    <p>Applications are checked against the authority's active profile revision and approved by a registration officer. Nothing is signed yet.</p>
    {notice && <p role="status">{notice}</p>}
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
        <td><span className="status-pill">{item.status}</span>{item.decision_reason && <><br /><small>{item.decision_reason}</small></>}</td>
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
