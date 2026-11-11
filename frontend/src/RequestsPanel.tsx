import { useEffect, useMemo, useRef, useState } from 'react';
import { ApiError, apiGet, apiPost } from './api';
import { ApplicationDecision } from './ApplicationDecision';
import { Icon, Notice, StatusBadge, Tabs, toast, type NoticeTone } from './ui';

export interface Application {
  application_id: string;
  ca_id: string;
  profile_id: string;
  revision: number;
  csr_sha256: string;
  subject_cn: string;
  dns_names: string[];
  validity_days: number;
  status: 'SUBMITTED' | 'APPROVED' | 'REJECTED' | 'ISSUING' | 'ISSUED' | 'RECONCILIATION_REQUIRED'
    | 'REVOCATION_REQUESTED' | 'REVOKED' | 'VOIDED';
  decision_reason: string | null;
  submitted_at: string;
  decided_at: string | null;
  certificate_serial_hex: string | null;
  certificate_sha256: string | null;
  open_revocation_id: string | null;
  open_revocation_reason_code: number | null;
  revocation_reason_code: number | null;
  revoked_at: string | null;
  /** Reconciliation of an ambiguous issuance (migration 0034). */
  void_status?: 'PROPOSED' | 'VOIDED' | null;
  void_signer_claimed?: boolean | null;
  void_proposed_by_reader?: boolean | null;
  void_serial_hex?: string | null;
  voided_at?: string | null;
}

interface Issuance {
  status: 'ISSUED' | 'RECONCILIATION_REQUIRED';
  certificate_pem: string | null;
  serial_hex: string | null;
}

// RFC 5280 reasons the laboratory accepts for end-entity certificates.
export const REASONS: [number, string][] = [
  [0, 'Unspecified'], [1, 'Key compromise'], [3, 'Affiliation changed'], [4, 'Superseded'],
  [5, 'Cessation of operation'], [9, 'Privilege withdrawn'],
];
export const reasonName = (code: number | null) => REASONS.find(([value]) => value === code)?.[1] ?? String(code);

type Filter = 'all' | 'decide' | 'approved' | 'issued' | 'revocation' | 'reconcile' | 'closed';
const FILTERS: { id: Filter; label: string; matches: (status: Application['status']) => boolean }[] = [
  { id: 'all', label: 'All', matches: () => true },
  { id: 'decide', label: 'Awaiting decision', matches: status => status === 'SUBMITTED' },
  { id: 'approved', label: 'Ready to issue', matches: status => status === 'APPROVED' },
  { id: 'issued', label: 'Issued', matches: status => status === 'ISSUED' || status === 'ISSUING' },
  { id: 'revocation', label: 'Revocation requested', matches: status => status === 'REVOCATION_REQUESTED' },
  { id: 'reconcile', label: 'Needs reconciliation', matches: status => status === 'RECONCILIATION_REQUIRED' },
  { id: 'closed', label: 'Closed', matches: status => status === 'REJECTED' || status === 'REVOKED' || status === 'VOIDED' },
];

export function writeError(failure: unknown, action: string): string {
  if (failure instanceof ApiError) {
    const id = failure.requestId ? ` Request ID: ${failure.requestId}.` : '';
    const reason: Record<number, string> = {
      400: 'the request is invalid: check every field (lowercase DNS names without wildcards, the common name among them, a validity in days, a reason).',
      403: 'your role or grant does not allow it, or you cannot decide on a request you made.',
      404: 'the record no longer exists for this authority, or the profile has no active revision.',
      409: 'it conflicts with the recorded state: already decided, issued or revoked, a request is already open, an earlier attempt is unresolved, or the authority or profile revision is no longer active.',
      422: 'it was refused: the CSR must be a P-256 PKCS#10 request whose only subject is CN=<common name>, and the names, zones and validity must fit the active profile of an ACTIVE authority.',
      502: 'the signing outcome is uncertain: it needs reconciliation and will not be signed again. Check that the laboratory signer holds this authority’s key.',
      503: 'the laboratory signer or the write database is not available.',
    };
    return `Could not ${action}: ${reason[failure.status] ?? `the server answered ${failure.status}.`}${id}`;
  }
  return `Could not ${action}: ${failure instanceof Error ? failure.message : 'the request failed.'}`;
}

function displayDate(value: string | null): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}

export function PemBlock({ title, pem, filename, note }: { title: string; pem: string; filename: string; note: string }) {
  const [copied, setCopied] = useState('');
  function download() {
    const url = URL.createObjectURL(new Blob([pem], { type: 'application/x-pem-file' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }
  return <div className="ui-pem">
    <div className="ui-pem-header"><strong>{title}</strong><div className="ui-actions">
      <button type="button" className="ui-button ui-button-secondary ui-button-sm" onClick={() => {
        void navigator.clipboard.writeText(pem).then(() => setCopied('Copied.'), () => setCopied('Select the text to copy it.'));
      }}><Icon name="copy" size={15} />Copy</button>
      <button type="button" className="ui-button ui-button-secondary ui-button-sm" onClick={download}><Icon name="download" size={15} />Download</button>
    </div></div>
    <textarea readOnly rows={7} value={pem} spellCheck={false} aria-label={title} />
    <p className="ui-hint">{note}{copied && ` ${copied}`}</p>
  </div>;
}

/**
 * Certificate requests of one authority (ADR-0016 to ADR-0018): a requester
 * submits a CSR made outside the browser; a registration officer other than
 * the requester decides; approved requests are issued once by the laboratory
 * signer; issued certificates are revoked when a different officer approves
 * a revocation request.
 */
export function RequestsPanel({ caId, token, canRequest, canDecide, onUnauthorized }: {
  caId: string; token: string; canRequest: boolean; canDecide: boolean; onUnauthorized: () => void;
}) {
  const [items, setItems] = useState<Application[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ tone: NoticeTone; text: string } | null>(null);
  const [reload, setReload] = useState(0);
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState<Filter>(canDecide ? 'decide' : 'all');
  const [formOpen, setFormOpen] = useState(false);
  const [profile, setProfile] = useState('server');
  const [commonName, setCommonName] = useState('');
  const [names, setNames] = useState('');
  const [days, setDays] = useState('30');
  const [pem, setPem] = useState('');
  const [open, setOpen] = useState<string | null>(null);
  const [reason, setReason] = useState('');
  const [reasonCode, setReasonCode] = useState(1);
  const [issued, setIssued] = useState<{ subject: string; pem: string; serial: string } | null>(null);
  const key = useRef(crypto.randomUUID());
  const base = `/v1/cas/${encodeURIComponent(caId)}/certificate-applications`;

  useEffect(() => {
    const controller = new AbortController();
    apiGet<Application[]>(base, token, controller.signal)
      .then(rows => { setItems(rows); setLoadError(null); })
      .catch(failure => {
        if (controller.signal.aborted) return;
        if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
        else setLoadError(failure instanceof Error ? failure.message : 'Could not load certificate requests.');
      });
    return () => controller.abort();
  }, [base, token, reload]);

  async function write<T>(path: string, body: unknown, action: string, done: (value: T, status: number) => string) {
    setBusy(true);
    try {
      const result = await apiPost<T>(path, token, body, key.current);
      setNotice(null);
      toast(done(result.value, result.status));
      setOpen(null);
      setReason('');
      return result.value;
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
      else setNotice({ tone: 'error', text: writeError(failure, action) });
      return null;
    } finally {
      key.current = crypto.randomUUID();
      setBusy(false);
      setReload(value => value + 1);
    }
  }

  const counts = useMemo(() => Object.fromEntries(FILTERS.map(f => [f.id, (items ?? []).filter(item => f.matches(item.status)).length])), [items]);
  const visible = (items ?? []).filter(item => FILTERS.find(f => f.id === filter)!.matches(item.status));
  const dnsNames = names.split(/[\s,]+/u).filter(Boolean);

  return <section className="ui-stack" aria-labelledby="requests-title">
    <div className="ui-section-header">
      <div><h2 id="requests-title" className="sr-only">Certificate requests</h2>
        <p>Requests are checked against the authority’s active profile revision and decided by a registration officer other than the requester. Approved requests are signed once by the laboratory signer.</p></div>
      {canRequest && !formOpen && <button type="button" className="ui-button ui-button-primary" onClick={() => setFormOpen(true)}><Icon name="plus" size={16} />New request</button>}
    </div>
    {notice && <Notice tone={notice.tone} onDismiss={() => setNotice(null)}>{notice.text}</Notice>}
    {issued && <PemBlock title={`Certificate for ${issued.subject}`} pem={issued.pem} filename={`${issued.subject}.crt`}
      note={`Serial ${issued.serial}. Check it with: openssl verify -CAfile root.crt -purpose sslserver cert.pem.`} />}

    {canRequest && formOpen && <form className="ui-card ui-form" onSubmit={event => {
      event.preventDefault();
      void write<{ application_id: string }>(base, { profile_id: profile, csr_pem: pem, common_name: commonName, dns_names: dnsNames, validity_days: Number(days) },
        'submit the request', () => `Request for ${commonName} submitted. A registration officer will review it.`).then(value => {
        if (value) { setFormOpen(false); setPem(''); setCommonName(''); setNames(''); setFilter('all'); }
      });
    }}>
      <div className="ui-card-header"><div><h3>New certificate request</h3><p>Generate the key and the CSR outside the browser; never paste a private key.</p></div></div>
      <div className="ui-form-grid">
        <label className="ui-field"><span>Profile ID</span><input value={profile} onChange={event => setProfile(event.target.value)} /></label>
        <label className="ui-field"><span>Validity (days)</span><input inputMode="numeric" value={days} onChange={event => setDays(event.target.value)} /></label>
        <label className="ui-field"><span>Common name</span><input value={commonName} placeholder="www.lab.invalid" onChange={event => setCommonName(event.target.value.trim())} /></label>
        <label className="ui-field"><span>DNS names (comma or space separated)</span><input value={names} placeholder="www.lab.invalid api.lab.invalid" onChange={event => setNames(event.target.value)} /></label>
        <label className="ui-field ui-field-wide"><span>CSR (PEM)</span><textarea rows={6} value={pem} onChange={event => setPem(event.target.value)} spellCheck={false} placeholder="-----BEGIN CERTIFICATE REQUEST-----" /></label>
      </div>
      <p className="ui-hint">For example: <code>openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout key.pem -subj "/CN={commonName || 'www.lab.invalid'}"</code></p>
      <div className="ui-actions ui-actions-end">
        <button type="button" className="ui-button ui-button-ghost" onClick={() => setFormOpen(false)}>Cancel</button>
        <button type="submit" className="ui-button ui-button-primary" disabled={busy || !commonName || dnsNames.length === 0 || !pem.trim()}>{busy ? 'Submitting…' : 'Submit application'}</button>
      </div>
    </form>}

    <div className="ui-card">
      <Tabs label="Request status" value={filter} onChange={setFilter} tabs={FILTERS.map(f => ({ id: f.id, label: f.label, count: counts[f.id] }))} />
      {loadError && <Notice tone="error" action={<button type="button" className="ui-button ui-button-secondary ui-button-sm" onClick={() => setReload(value => value + 1)}>Retry</button>}>{loadError}</Notice>}
      {!items && !loadError && <p className="ui-empty">Loading requests…</p>}
      {items && visible.length === 0 && <p className="ui-empty">{items.length === 0 ? 'No certificate requests for this authority yet.' : 'No request in this view.'}</p>}
      {visible.length > 0 && <div className="ui-table-wrap"><table className="ui-table" aria-label="Certificate applications">
        <thead><tr><th>Common name</th><th>Status</th><th>Profile</th><th>Submitted</th><th className="ui-col-actions">Actions</th></tr></thead>
        <tbody>{visible.map(item => {
          const expanded = open === item.application_id;
          const canIssue = item.status === 'APPROVED' && (canRequest || canDecide);
          const canAskRevocation = item.status === 'ISSUED' && (canRequest || canDecide);
          const decideApplication = canDecide && item.status === 'SUBMITTED';
          const decideRevocation = canDecide && item.status === 'REVOCATION_REQUESTED' && item.open_revocation_id;
          // Reconciliation (ADR-0020): one officer proposes, another confirms.
          const proposeVoid = canDecide && item.status === 'RECONCILIATION_REQUIRED' && !item.void_status;
          const confirmVoid = canDecide && item.status === 'RECONCILIATION_REQUIRED' && item.void_status === 'PROPOSED' && !item.void_proposed_by_reader;
          return [<tr key={item.application_id} className={expanded ? 'ui-row-open' : undefined}>
            <td><strong>{item.subject_cn}</strong><div className="ui-sub">{item.dns_names.join(', ')}</div></td>
            <td><StatusBadge status={item.status} />
              {item.certificate_serial_hex && <div className="ui-sub mono">Serial {item.certificate_serial_hex.slice(0, 16)}…</div>}
              {item.revoked_at && <div className="ui-sub">Revoked {displayDate(item.revoked_at)} · {reasonName(item.revocation_reason_code)}</div>}
              {item.status === 'REVOCATION_REQUESTED' && <div className="ui-sub">Reason: {reasonName(item.open_revocation_reason_code)}</div>}
              {item.status === 'RECONCILIATION_REQUIRED' && <div className="ui-sub">{item.void_status === 'PROPOSED'
                ? (item.void_proposed_by_reader ? 'You proposed to void it; another officer must confirm.' : 'A void was proposed; another officer must confirm.')
                : 'Signing outcome unknown: never re-signed.'}</div>}
              {item.void_status && item.void_signer_claimed !== null && item.void_signer_claimed !== undefined && <div className="ui-sub">{item.void_signer_claimed ? 'The signer had claimed it: a certificate may exist.' : 'The signer never claimed it.'}</div>}
              {item.status === 'VOIDED' && item.void_serial_hex && <div className="ui-sub mono">Serial {item.void_serial_hex.slice(0, 16)}… listed on CRLs since {displayDate(item.voided_at ?? null)}</div>}
              {item.decision_reason && <div className="ui-sub">“{item.decision_reason}”</div>}</td>
            <td>{item.profile_id} r{item.revision}<div className="ui-sub">{item.validity_days} days</div></td>
            <td>{displayDate(item.submitted_at)}</td>
            <td className="ui-col-actions"><div className="ui-actions">
              {canIssue && <button type="button" className="ui-button ui-button-primary ui-button-sm" disabled={busy}
                onClick={() => void write<Issuance>(`${base}/${item.application_id}/issuance`, {}, 'issue the certificate', (value, status) => {
                  if (value.certificate_pem && value.serial_hex) setIssued({ subject: item.subject_cn, pem: value.certificate_pem, serial: value.serial_hex });
                  return status === 201 ? `Certificate for ${item.subject_cn} issued.` : `The certificate for ${item.subject_cn} was already issued.`;
                })}>Issue certificate</button>}
              {(decideApplication || decideRevocation || canAskRevocation || proposeVoid || confirmVoid) && <button type="button" className="ui-button ui-button-secondary ui-button-sm"
                aria-expanded={expanded} onClick={() => { setOpen(expanded ? null : item.application_id); setReason(''); }}>
                {decideApplication ? 'Review' : decideRevocation ? 'Review revocation' : proposeVoid ? 'Reconcile…' : confirmVoid ? 'Review void' : 'Revoke…'}</button>}
            </div></td>
          </tr>,
          expanded && <tr key={`${item.application_id}-form`} className="ui-row-detail"><td colSpan={5}>
            {(proposeVoid || confirmVoid) && <Notice tone="warning">{proposeVoid
              ? 'Voiding closes this request for good. Its serial is never reused and is listed on every later CRL, in case the signer produced a certificate. A second registration officer must confirm. The requester can then submit a new request.'
              : `Confirming lists serial ${item.void_serial_hex ?? ''} on the next CRL and closes the request. ${item.void_signer_claimed ? 'The signer had claimed this intent, so a certificate with this serial may exist.' : 'The signer never claimed this intent.'}`}</Notice>}
            <form className="ui-inline-form" onSubmit={event => event.preventDefault()}>
              {canAskRevocation && <label className="ui-field"><span>Reason</span><select aria-label={`Revocation reason for ${item.subject_cn}`} value={reasonCode} onChange={event => setReasonCode(Number(event.target.value))}>
                {REASONS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>}
              <label className="ui-field ui-field-grow"><span>{canAskRevocation || proposeVoid || confirmVoid ? 'Explanation' : 'Decision reason'}</span>
                <input autoFocus aria-label={canAskRevocation ? `Revocation explanation for ${item.subject_cn}` : proposeVoid || confirmVoid ? `Void explanation for ${item.subject_cn}` : decideRevocation ? `Revocation decision reason for ${item.subject_cn}` : `Decision reason for ${item.subject_cn}`}
                  value={reason} onChange={event => setReason(event.target.value)} /></label>
              <div className="ui-actions">
                {decideApplication && <ApplicationDecision caId={caId} token={token} item={item} reason={reason}
                  onUnauthorized={onUnauthorized} onCancel={() => setOpen(null)}
                  onError={text => setNotice({ tone: 'error', text })}
                  onDecided={message => { toast(message); setNotice(null); setOpen(null); setReason(''); setReload(value => value + 1); }} />}
                {decideRevocation && <>
                  <button type="button" className="ui-button ui-button-danger ui-button-sm" disabled={busy || !reason.trim()} onClick={() => void write(`${base}/${item.application_id}/revocation-requests/${item.open_revocation_id}/decision`, { decision: 'approve', reason: reason.trim() }, 'approve the revocation', () => `${item.subject_cn} revoked. It appears on the next CRL.`)}>Approve revocation</button>
                  <button type="button" className="ui-button ui-button-secondary ui-button-sm" disabled={busy || !reason.trim()} onClick={() => void write(`${base}/${item.application_id}/revocation-requests/${item.open_revocation_id}/decision`, { decision: 'reject', reason: reason.trim() }, 'reject the revocation', () => `Revocation of ${item.subject_cn} rejected.`)}>Reject revocation</button>
                </>}
                {canAskRevocation && <button type="button" className="ui-button ui-button-danger ui-button-sm" disabled={busy || !reason.trim()} onClick={() => void write(`${base}/${item.application_id}/revocation-requests`, { reason_code: reasonCode, reason: reason.trim() }, 'request the revocation', () => `Revocation of ${item.subject_cn} requested. A registration officer who did not ask must approve it.`)}>Request revocation</button>}
                {proposeVoid && <button type="button" className="ui-button ui-button-danger ui-button-sm" disabled={busy || !reason.trim()} onClick={() => void write<{ signer_claimed: boolean }>(`${base}/${item.application_id}/void-proposal`, { reason: reason.trim() }, 'propose the void', value => `Void of ${item.subject_cn} proposed${value.signer_claimed ? ' (the signer had claimed it)' : ''}. Another officer must confirm.`)}>Propose void</button>}
                {confirmVoid && <button type="button" className="ui-button ui-button-danger ui-button-sm" disabled={busy || !reason.trim()} onClick={() => void write(`${base}/${item.application_id}/void-confirmation`, { reason: reason.trim() }, 'confirm the void', () => `${item.subject_cn} voided. Its serial appears on the next CRL.`)}>Confirm void</button>}
                {!decideApplication && <button type="button" className="ui-button ui-button-ghost ui-button-sm" onClick={() => setOpen(null)}>Cancel</button>}
              </div>
            </form>
          </td></tr>];
        })}</tbody>
      </table></div>}
    </div>
  </section>;
}
