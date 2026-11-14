import { useRef, useState } from 'react';
import { ApiError, apiPost } from './api';
import { Notice } from './ui';
import type { CaProposal } from './CaProposalPanel';

interface Claim {
  decision: 'approve' | 'reject';
  claim: string;
  key_id: string;
  issued_at: string;
}

interface Props {
  token: string;
  proposal: CaProposal;
  canAdminister: boolean;
  canApprove: boolean;
  onChanged: (message: string) => void;
  onUnauthorized: () => void;
}

const CLAIM_PATTERN = /^trust-platform\/ca-change-decision\/v1;decision=(approve|reject);action=(reactivate|retire);[^\r\n]{1,3900}$/u;
const ACTION_LABEL = { reactivate: 'reactivation', retire: 'retirement' } as const;

function failureMessage(failure: unknown, fallback: string): string {
  if (failure instanceof ApiError) {
    if (failure.status === 403) return 'Your role or grant does not allow this, or separation of duties forbids it (you requested or decided on this change).';
    if (failure.status === 409) return 'The CA or its change request is no longer in a state that allows this. Reload it.';
    if (failure.status === 422) return 'Refused: the signature does not verify with your registered CA approver key, or the issuer certificate has expired. Nothing was recorded.';
  }
  return failure instanceof Error ? failure.message : fallback;
}

/**
 * Operation of an activated CA (ADR-0015). Suspension is immediate, by one
 * administrator. Reactivation and retirement are change requests that two CA
 * approvers sign outside the browser and an administrator who did not decide
 * applies; retirement also retires the CA's active profile revisions and is
 * final. The server enforces every rule; the console offers no override.
 */
export function CaOperation({ token, proposal, canAdminister, canApprove, onChanged, onUnauthorized }: Props) {
  const [reason, setReason] = useState('');
  const [claim, setClaim] = useState<Claim | null>(null);
  const [signature, setSignature] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // One key per intended change, so a retry after a lost response is a replay.
  const writeKey = useRef(crypto.randomUUID());
  const base = `/v1/ca-proposals/${encodeURIComponent(proposal.ca_id)}`;
  const request = proposal.change_request_id ? `${base}/change-requests/${encodeURIComponent(proposal.change_request_id)}` : null;
  const action = proposal.change_action;

  async function write(path: string, body: unknown, done: (value: Record<string, unknown>) => string) {
    setBusy(true);
    setError(null);
    try {
      const result = await apiPost<Record<string, unknown>>(path, token, body, writeKey.current);
      writeKey.current = crypto.randomUUID();
      setReason('');
      setClaim(null);
      onChanged(done(result.value));
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
      else {
        writeKey.current = crypto.randomUUID();
        setError(failureMessage(failure, 'The change failed.'));
      }
    } finally {
      setBusy(false);
    }
  }

  async function prepare(decision: Claim['decision']) {
    if (!request || !action) return;
    setBusy(true);
    setError(null);
    setSignature('');
    try {
      const response = await fetch(`${request}/decision-claims`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision }),
        credentials: 'omit',
        cache: 'no-store',
      });
      if (response.status === 401) { onUnauthorized(); return; }
      if (!response.ok) throw new ApiError(response.status, `Could not prepare the decision (${response.status}).`);
      const value = await response.json() as Partial<Claim>;
      if (value.decision !== decision || typeof value.claim !== 'string' || !CLAIM_PATTERN.test(value.claim)
        || !value.claim.includes(`;action=${action};request_id=${proposal.change_request_id};ca_id=${proposal.ca_id};`)
        || typeof value.key_id !== 'string' || typeof value.issued_at !== 'string') {
        throw new Error('The management API returned an invalid change claim.');
      }
      writeKey.current = crypto.randomUUID();
      setClaim(value as Claim);
    } catch (failure) {
      setError(failureMessage(failure, 'Could not prepare the decision.'));
    } finally {
      setBusy(false);
    }
  }

  function record() {
    if (!claim || !request) return;
    const encoded = signature.replace(/\s+/gu, '');
    if (!/^[A-Za-z0-9+/]{8,120}={0,2}$/u.test(encoded)) {
      setError('Paste the base64 DER signature produced by your signing command.');
      return;
    }
    void write(`${request}/decisions`, { decision: claim.decision, issued_at: claim.issued_at, signature_der_base64: encoded },
      value => value.request_status === 'APPROVED'
        ? `The ${ACTION_LABEL[action as 'reactivate' | 'retire']} of ${proposal.display_name} is now approved.`
        : `Your decision on ${proposal.display_name} was recorded (${String(value.request_status)}).`);
  }

  const state = proposal.lifecycle_status;
  if (state !== 'ACTIVE' && state !== 'SUSPENDED') return null;
  const validReason = reason.trim() === reason && reason.length > 0 && reason.length <= 500;
  const command = claim ? `printf '%s' '${claim.claim}' | openssl dgst -sha256 -sign .lab-keys/<your-ca-approver-key>.pem | openssl base64 -A` : '';
  return <div className="ca-action-block">
    <strong className="ca-action-title">Operation ({state})</strong>
    {canAdminister && !request && <>
      <label className="ui-field"><span>Reason for {proposal.display_name}</span>
        <input value={reason} maxLength={500} onChange={event => setReason(event.target.value)} /></label>
      <div className="ui-actions">
        {state === 'ACTIVE' && <button type="button" className="ui-button ui-button-primary ui-button-sm" disabled={busy || !validReason}
          onClick={() => void write(`${base}/suspension`, { reason }, () => `${proposal.display_name} is now SUSPENDED.`)}>Suspend this CA</button>}
        {state === 'SUSPENDED' && <button type="button" className="ui-button ui-button-primary ui-button-sm" disabled={busy || !validReason}
          onClick={() => void write(`${base}/change-requests`, { action: 'reactivate', reason }, () => `Reactivation of ${proposal.display_name} requested.`)}>Request reactivation</button>}
        <button type="button" className="ui-button ui-button-ghost ui-button-sm" disabled={busy || !validReason}
          onClick={() => void write(`${base}/change-requests`, { action: 'retire', reason }, () => `Retirement of ${proposal.display_name} requested.`)}>Request retirement</button>
      </div>
      <p className="ui-hint">Suspension takes effect at once and blocks profile activations. Reactivation and retirement need two CA approvers; retirement also retires the CA's active profile revisions and cannot be undone.</p>
    </>}
    {request && action && <>
      <p>Pending {ACTION_LABEL[action]} ({proposal.change_status}, {proposal.change_approval_count ?? 0}/2 approvals): {proposal.change_reason}</p>
      {canApprove && proposal.change_status === 'OPEN' && !claim && <div className="ui-actions">
        <button type="button" className="ui-button ui-button-primary ui-button-sm" disabled={busy} onClick={() => void prepare('approve')}>Prepare approval of the {ACTION_LABEL[action]}</button>
        <button type="button" className="ui-button ui-button-ghost ui-button-sm" disabled={busy} onClick={() => void prepare('reject')}>Prepare rejection of the {ACTION_LABEL[action]}</button>
      </div>}
      {claim && <>
        <label className="ui-field"><span>Change claim to sign ({claim.decision}, key {claim.key_id}, valid 10 minutes)</span>
          <textarea readOnly rows={4} value={claim.claim} className="mono" /></label>
        <pre className="decision-command">{command}</pre>
        <label className="ui-field"><span>Change decision signature (base64, DER)</span>
          <textarea rows={3} value={signature} onChange={event => { setSignature(event.target.value); setError(null); }} spellCheck={false} /></label>
        <div className="ui-actions">
          <button type="button" className="ui-button ui-button-primary ui-button-sm" disabled={busy} onClick={record}>{busy ? 'Verifying…' : 'Record change decision'}</button>
          <button type="button" className="ui-button ui-button-ghost ui-button-sm" disabled={busy} onClick={() => setClaim(null)}>Cancel</button>
        </div>
      </>}
      {canAdminister && proposal.change_status === 'APPROVED' && <button type="button" className="ui-button ui-button-primary ui-button-sm" disabled={busy}
        onClick={() => void write(`${request}/application`, {}, value => `${proposal.display_name} is now ${String(value.operational_state)}.`)}>
        Apply the {ACTION_LABEL[action]}</button>}
    </>}
    {error && <Notice tone="error" onDismiss={() => setError(null)}>{error}</Notice>}
  </div>;
}
