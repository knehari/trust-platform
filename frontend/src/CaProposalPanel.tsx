import { useEffect, useRef, useState } from 'react';
import { ApiError, apiGet, apiPost } from './api';
import { CaDecision } from './CaDecision';
import { CaOperation } from './CaOperation';
import { Icon, Notice, StatusBadge } from './ui';

export interface CaProposal {
  ca_id: string;
  display_name: string;
  policy_version: string;
  suite_id: string;
  /** Only ACTIVE is a CA; no state issues anything yet (ADR-0013, ADR-0014). */
  lifecycle_status: 'PROPOSED' | 'KEY_ATTESTED' | 'APPROVED' | 'REJECTED' | 'ACTIVE' | 'SUSPENDED' | 'RETIRED';
  proposed_at: string;
  certificate_sha256: string | null;
  spki_sha256: string | null;
  not_before: string | null;
  not_after: string | null;
  custody: string | null;
  registered_at: string | null;
  approval_count: number;
  decided_at: string | null;
  activated_at: string | null;
  state_changed_at: string | null;
  /** The open or approved reactivation or retirement request (ADR-0015). */
  change_request_id: string | null;
  change_action: 'reactivate' | 'retire' | null;
  change_status: 'OPEN' | 'APPROVED' | null;
  change_approval_count: number | null;
  change_reason: string | null;
}

interface Props {
  token: string;
  canAdminister: boolean;
  canApprove: boolean;
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
export function CaProposalPanel({ token, canAdminister, canApprove, onUnauthorized }: Props) {
  const [items, setItems] = useState<CaProposal[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  const [name, setName] = useState('');
  const [policy, setPolicy] = useState('v1');
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [pem, setPem] = useState<Record<string, string>>({});
  const [rowError, setRowError] = useState<Record<string, string>>({});
  const [notice, setNotice] = useState('');
  const [open, setOpen] = useState<string | null>(null);
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

  // A row needs a decision from this person: show its actions at once.
  const pending = (item: CaProposal) => (canAdminister && (item.lifecycle_status === 'PROPOSED' || item.lifecycle_status === 'APPROVED'))
    || (canApprove && item.lifecycle_status === 'KEY_ATTESTED')
    || (item.change_status === 'OPEN' && canApprove) || (item.change_status === 'APPROVED' && canAdminister);
  const operable = (item: CaProposal) => canAdminister && (item.lifecycle_status === 'ACTIVE' || item.lifecycle_status === 'SUSPENDED');

  return <section className="ui-stack ca-proposals" aria-labelledby="ca-proposals-title">
    <div className="ui-section-header"><div><h2 id="ca-proposals-title">CA proposals</h2>
      <p>A proposal becomes a certificate authority only after two CA approvers approve it and an administrator who did not decide activates it.</p></div></div>
    {notice && <Notice tone="success" onDismiss={() => setNotice('')}>{notice}</Notice>}
    {canAdminister && <form className="ui-card" onSubmit={event => void propose(event)}>
      <div className="ui-inline-form">
        <label className="ui-field ui-field-grow"><span>Display name</span><input value={name} maxLength={255} placeholder="Lab Issuing CA" onChange={event => setName(event.target.value)} required /></label>
        <label className="ui-field"><span>Policy version</span><input value={policy} maxLength={128} onChange={event => setPolicy(event.target.value)} required /></label>
        <button type="submit" className="ui-button ui-button-primary" disabled={busy || !name.trim() || !policy.trim()}><Icon name="plus" size={16} />{busy ? 'Saving…' : 'Propose this CA'}</button>
      </div>
      <p className="ui-hint">Signing suite: <code>{SUITE}</code>, the only suite a laboratory CA can be proposed with.</p>
      {formError && <Notice tone="error" onDismiss={() => setFormError(null)}>{formError}</Notice>}
    </form>}
    {loadError && <Notice tone="error">{loadError}</Notice>}
    <div className="ui-card">
      {!items && !loadError && <p className="ui-empty">Loading CA proposals…</p>}
      {items && items.length === 0 && <p className="ui-empty">No CA proposals are visible to your account.</p>}
      {items && items.length > 0 && <div className="ui-table-wrap"><table className="ui-table" aria-label="CA proposals">
        <thead><tr><th>Authority</th><th>Status</th><th>Policy</th><th>Issuer certificate</th><th className="ui-col-actions">Actions</th></tr></thead>
        <tbody>{items.map(item => {
          const showActions = pending(item) || open === item.ca_id;
          return [<tr key={item.ca_id} data-ca-proposal={item.ca_id} className={showActions ? 'ui-row-open' : undefined}>
            <td><strong>{item.display_name}</strong><div className="ui-sub mono">{item.ca_id}</div></td>
            <td><StatusBadge status={item.lifecycle_status} />{item.approval_count > 0 && <div className="ui-sub">{item.approval_count}/2 approvals</div>}
              {item.change_status && <div className="ui-sub">Change {item.change_status.toLowerCase()}</div>}</td>
            <td>{item.policy_version}<div className="ui-sub">{item.suite_id}</div></td>
            <td>{item.certificate_sha256
              ? <><span className="mono" title={item.certificate_sha256}>{item.certificate_sha256.slice(0, 16)}…</span><div className="ui-sub">{item.not_before?.slice(0, 10)} → {item.not_after?.slice(0, 10)} · {item.custody}</div></>
              : <span className="muted">Not registered</span>}</td>
            <td className="ui-col-actions">{operable(item) && !pending(item) && <button type="button" className="ui-button ui-button-secondary ui-button-sm" aria-expanded={open === item.ca_id}
              onClick={() => setOpen(open === item.ca_id ? null : item.ca_id)}>Operations</button>}</td>
          </tr>,
          showActions && <tr key={`${item.ca_id}-actions`} className="ui-row-detail"><td colSpan={5}><div className="ca-actions">
            <span className="sr-only">Actions for {item.display_name}</span>
            {item.lifecycle_status === 'PROPOSED' && canAdminister && <div className="ui-stack">
              <label className="ui-field"><span>Certificate (PEM) for “{item.display_name}”</span><textarea rows={4} value={pem[item.ca_id] ?? ''} placeholder="-----BEGIN CERTIFICATE-----" onChange={event => setPem(values => ({ ...values, [item.ca_id]: event.target.value }))} /></label>
              <p className="ui-hint">Generate the key and the root outside the platform: <code>scripts/lab/create-lab-root.sh "{item.display_name}"</code>. Never paste a private key.</p>
              <div className="ui-actions"><button type="button" className="ui-button ui-button-primary ui-button-sm" disabled={busy || !(pem[item.ca_id] ?? '').trim()} onClick={() => void register(item.ca_id)}>Register certificate</button></div>
              {rowError[item.ca_id] && <Notice tone="error" onDismiss={() => setRowError(errors => ({ ...errors, [item.ca_id]: '' }))}>{rowError[item.ca_id]}</Notice>}
            </div>}
            <CaDecision token={token} proposal={item} canDecide={canApprove} canActivate={canAdminister}
              onChanged={message => { setNotice(message); setReload(value => value + 1); }} onUnauthorized={onUnauthorized} />
            <CaOperation token={token} proposal={item} canAdminister={canAdminister} canApprove={canApprove}
              onChanged={message => { setNotice(message); setOpen(null); setReload(value => value + 1); }} onUnauthorized={onUnauthorized} />
          </div></td></tr>];
        })}</tbody>
      </table></div>}
    </div>
  </section>;
}
