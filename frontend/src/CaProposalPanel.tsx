import { useEffect, useRef, useState } from 'react';
import { ApiError, apiGet, apiPost } from './api';

export interface CaProposal {
  ca_id: string;
  display_name: string;
  policy_version: string;
  suite_id: string;
  /** A proposal is not a CA: neither state issues anything (ADR-0013). */
  lifecycle_status: 'PROPOSED' | 'KEY_ATTESTED';
  proposed_at: string;
  certificate_sha256: string | null;
  spki_sha256: string | null;
  not_before: string | null;
  not_after: string | null;
  custody: string | null;
  registered_at: string | null;
}

interface Props {
  token: string;
  onUnauthorized: () => void;
}

const SUITE = 'ecdsa-p256-sha256';

function message(failure: unknown, action: 'propose' | 'register'): string {
  if (failure instanceof ApiError) {
    if (failure.status === 403) return 'Your account has no CA administrator grant.';
    if (failure.status === 409) return action === 'register'
      ? 'This proposal already has a certificate, or this key is registered for another CA.'
      : 'This request conflicts with a recorded one. Reload and try again.';
    if (failure.status === 422) return action === 'register'
      ? 'The certificate was refused: it must be a currently valid, self-signed P-256 CA root (ECDSA SHA-256, basic constraints and key usage critical) whose only subject attribute is the proposed display name.'
      : 'Only the ecdsa-p256-sha256 suite can be proposed.';
  }
  return failure instanceof Error ? failure.message : 'The request failed.';
}

/**
 * CA proposals for platform administrators (ADR-0013). The private key is
 * generated outside the platform (scripts/lab/create-lab-root.sh); only the
 * certificate is pasted here. The server verifies it and checks the grant.
 */
export function CaProposalPanel({ token, onUnauthorized }: Props) {
  const [items, setItems] = useState<CaProposal[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  const [name, setName] = useState('');
  const [policy, setPolicy] = useState('v1');
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [pem, setPem] = useState<Record<string, string>>({});
  const [rowError, setRowError] = useState<Record<string, string>>({});
  // One key per intended change, so a retry after a lost response is a replay.
  const proposeKey = useRef(crypto.randomUUID());
  const registerKeys = useRef<Record<string, string>>({});

  useEffect(() => {
    const controller = new AbortController();
    apiGet<CaProposal[]>('/v1/ca-proposals', token, controller.signal)
      .then(rows => { setItems(rows); setLoadError(null); })
      .catch(failure => {
        if (controller.signal.aborted) return;
        if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
        else setLoadError(failure instanceof Error ? failure.message : 'Could not load CA proposals.');
      });
    return () => controller.abort();
  }, [token, reload]);

  async function propose(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setFormError(null);
    try {
      await apiPost('/v1/ca-proposals', token, { display_name: name.trim(), policy_version: policy.trim(), suite_id: SUITE }, proposeKey.current);
      proposeKey.current = crypto.randomUUID();
      setName('');
      setReload(value => value + 1);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
      else setFormError(message(failure, 'propose'));
    } finally {
      setBusy(false);
    }
  }

  async function register(caId: string) {
    setBusy(true);
    setRowError(errors => ({ ...errors, [caId]: '' }));
    registerKeys.current[caId] ??= crypto.randomUUID();
    try {
      await apiPost(`/v1/ca-proposals/${encodeURIComponent(caId)}/issuer-certificate`, token,
        { certificate_pem: pem[caId] ?? '' }, registerKeys.current[caId]);
      delete registerKeys.current[caId];
      setReload(value => value + 1);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
      else {
        // A refused certificate is a different request next time.
        delete registerKeys.current[caId];
        setRowError(errors => ({ ...errors, [caId]: message(failure, 'register') }));
      }
    } finally {
      setBusy(false);
    }
  }

  return <section className="panel ca-proposals" aria-labelledby="ca-proposals-title">
    <div className="panel-header"><h2 id="ca-proposals-title">CA proposals</h2></div>
    <p>A proposal is not a certificate authority: it issues nothing until it is approved and activated, which this laboratory cannot do yet.</p>
    <form className="subtle-panel" onSubmit={event => void propose(event)}>
      <label>Display name <input value={name} maxLength={255} onChange={event => setName(event.target.value)} required /></label>
      <label>Policy version <input value={policy} maxLength={128} onChange={event => setPolicy(event.target.value)} required /></label>
      <p>Signing suite: <code>{SUITE}</code> (the only suite a laboratory CA can be proposed with).</p>
      <button type="submit" disabled={busy || !name.trim() || !policy.trim()}>{busy ? 'Saving…' : 'Propose this CA'}</button>
      {formError && <p className="lookup-error" role="alert">{formError}</p>}
    </form>
    {loadError && <div className="notice error" role="alert">{loadError}</div>}
    {items && items.length === 0 && <p>No CA proposals are visible to your account.</p>}
    {items && items.length > 0 && <table className="data-table" aria-label="CA proposals">
      <thead><tr><th>Display name</th><th>Status</th><th>Policy</th><th>Issuer certificate</th></tr></thead>
      <tbody>{items.map(item => <tr key={item.ca_id} data-ca-proposal={item.ca_id}>
        <td><b>{item.display_name}</b><br /><small>{item.ca_id}</small></td>
        <td><span className="status-pill">{item.lifecycle_status}</span></td>
        <td>{item.policy_version}<br /><small>{item.suite_id}</small></td>
        <td>{item.lifecycle_status === 'KEY_ATTESTED'
          ? <><small>SHA-256 {item.certificate_sha256}</small><br /><small>Valid {item.not_before} – {item.not_after}</small><br /><small>Custody: {item.custody} (software key, laboratory only)</small></>
          : <>
            <label>Certificate (PEM) for “{item.display_name}”<textarea rows={4} value={pem[item.ca_id] ?? ''} onChange={event => setPem(values => ({ ...values, [item.ca_id]: event.target.value }))} /></label>
            <button type="button" disabled={busy || !(pem[item.ca_id] ?? '').trim()} onClick={() => void register(item.ca_id)}>Register certificate</button>
            {rowError[item.ca_id] && <p className="lookup-error" role="alert">{rowError[item.ca_id]}</p>}
            <p><small>Generate the key and certificate outside the platform: <code>scripts/lab/create-lab-root.sh "{item.display_name}"</code>. Never paste a private key.</small></p>
          </>}
        </td>
      </tr>)}</tbody>
    </table>}
  </section>;
}
