import { useRef, useState } from 'react';
import { ApiError, apiPost } from './api';
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
  canDecide: boolean;
  canActivate: boolean;
  onChanged: (message: string) => void;
  onUnauthorized: () => void;
}

const CLAIM_PATTERN = /^trust-platform\/ca-decision\/v1;decision=(approve|reject);[^\r\n]{1,3900}$/u;

/**
 * Signed decision on a key-attested CA proposal, and activation of an
 * approved one (ADR-0014). The console never holds a key: it shows the exact
 * claim the server built, the CA approver signs it outside the browser, and
 * the server verifies the signature before recording anything. Activation
 * names the approved certificate's digest; the server checks the grant, that
 * the administrator did not decide, and the stored certificate again.
 */
export function CaDecision({ token, proposal, canDecide, canActivate, onChanged, onUnauthorized }: Props) {
  const [claim, setClaim] = useState<Claim | null>(null);
  const [signature, setSignature] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const recordKey = useRef('');
  const activationKey = useRef(crypto.randomUUID());
  const base = `/v1/ca-proposals/${encodeURIComponent(proposal.ca_id)}`;

  async function prepare(decision: Claim['decision']) {
    setBusy(true);
    setError(null);
    setSignature('');
    try {
      const response = await fetch(`${base}/decision-claims`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision }),
        credentials: 'omit',
        cache: 'no-store',
      });
      if (response.status === 401) { onUnauthorized(); return; }
      if (!response.ok) {
        throw new Error(response.status === 403 ? 'Your grant or key does not allow this decision, or you proposed this CA or registered its certificate.'
          : response.status === 409 ? 'This proposal is no longer awaiting your decision.'
          : response.status === 422 ? 'The issuer certificate has expired.'
          : `Could not prepare the decision (${response.status}).`);
      }
      const value = await response.json() as Partial<Claim>;
      if (value.decision !== decision || typeof value.claim !== 'string' || !CLAIM_PATTERN.test(value.claim)
        || !value.claim.includes(`;ca_id=${proposal.ca_id};`)
        || !value.claim.includes(`;certificate_sha256=${proposal.certificate_sha256};`)
        || typeof value.key_id !== 'string' || typeof value.issued_at !== 'string') {
        throw new Error('The management API returned an invalid decision claim.');
      }
      recordKey.current = crypto.randomUUID();
      setClaim(value as Claim);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Could not prepare the decision.');
    } finally {
      setBusy(false);
    }
  }

  async function record() {
    if (!claim) return;
    const encoded = signature.replace(/\s+/gu, '');
    if (!/^[A-Za-z0-9+/]{8,120}={0,2}$/u.test(encoded)) {
      setError('Paste the base64 DER signature produced by your signing command.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const result = await apiPost<{ lifecycle_status?: unknown; approval_count?: unknown }>(`${base}/decisions`, token,
        { decision: claim.decision, issued_at: claim.issued_at, signature_der_base64: encoded }, recordKey.current);
      const status = result.value.lifecycle_status;
      if (typeof status !== 'string' || typeof result.value.approval_count !== 'number') {
        throw new Error('The management API returned an invalid decision.');
      }
      setClaim(null);
      onChanged(status === 'KEY_ATTESTED'
        ? `Your approval of ${proposal.display_name} was recorded (${result.value.approval_count}/2).`
        : `${proposal.display_name} is now ${status}.`);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
      else setError(failure instanceof ApiError && failure.status === 422
        ? 'The signature does not verify with your registered CA approver key over this exact claim. Nothing was recorded.'
        : failure instanceof ApiError && failure.status === 409
          ? 'The claim expired or the proposal was decided meanwhile. Prepare the decision again.'
          : failure instanceof Error ? failure.message : 'Could not record the decision.');
    } finally {
      setBusy(false);
    }
  }

  async function activate() {
    setBusy(true);
    setError(null);
    try {
      const result = await apiPost<{ lifecycle_status?: unknown }>(`${base}/activation`, token,
        { certificate_sha256: proposal.certificate_sha256 }, activationKey.current);
      if (result.value.lifecycle_status !== 'ACTIVE') throw new Error('The management API returned an invalid activation.');
      activationKey.current = crypto.randomUUID();
      onChanged(`${proposal.display_name} is now an ACTIVE CA.`);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
      else setError(failure instanceof ApiError && failure.status === 403
        ? 'Your grant does not allow activation, or you decided on this proposal.'
        : failure instanceof ApiError && failure.status === 422
          ? 'The stored issuer certificate no longer verifies (expired or refused). Nothing was activated.'
          : failure instanceof ApiError && failure.status === 409
            ? 'This proposal is no longer approved and awaiting activation. Reload it.'
            : failure instanceof Error ? failure.message : 'Could not activate the CA.');
    } finally {
      setBusy(false);
    }
  }

  const status = proposal.lifecycle_status;
  if (!(canDecide && status === 'KEY_ATTESTED') && !(canActivate && status === 'APPROVED')) return null;
  const command = claim ? `printf '%s' '${claim.claim}' | openssl dgst -sha256 -sign .lab-keys/<your-ca-approver-key>.pem | openssl base64 -A` : '';
  return <div className="subtle-panel ca-decision">
    {canDecide && status === 'KEY_ATTESTED' && <>
      <b>Decision ({proposal.approval_count}/2 approvals)</b>
      {!claim && <div className="form-actions">
        <button type="button" disabled={busy} onClick={() => void prepare('approve')}>Prepare CA approval</button>
        <button type="button" className="link-button" disabled={busy} onClick={() => void prepare('reject')}>Prepare CA rejection</button>
      </div>}
      {claim && <>
        <label className="form-field"><span>CA claim to sign ({claim.decision}, key {claim.key_id}, valid 10 minutes)</span>
          <textarea readOnly rows={4} value={claim.claim} className="mono" /></label>
        <p>Sign the exact claim with your registered CA approver key, outside the browser:</p>
        <pre className="decision-command">{command}</pre>
        <label className="form-field"><span>CA decision signature (base64, DER)</span>
          <textarea rows={3} value={signature} onChange={event => { setSignature(event.target.value); setError(null); }} spellCheck={false} /></label>
        <div className="form-actions">
          <button type="button" disabled={busy} onClick={() => void record()}>{busy ? 'Verifying…' : claim.decision === 'approve' ? 'Record CA approval' : 'Record CA rejection'}</button>
          <button type="button" className="link-button" disabled={busy} onClick={() => { setClaim(null); setError(null); }}>Cancel</button>
        </div>
      </>}
      <p><small>Two different CA approvers with different registered keys must approve; one rejection is final. The proposer and the registrant cannot decide.</small></p>
    </>}
    {canActivate && status === 'APPROVED' && <>
      <button type="button" disabled={busy} onClick={() => void activate()}>{busy ? 'Activating…' : 'Activate this CA'}</button>
      <p><small>Activation creates the CA with its attested suite as its only signing capability. You cannot activate a CA you decided on. No issuance path uses the new CA yet.</small></p>
    </>}
    {error && <p className="lookup-error" role="alert">{error}</p>}
  </div>;
}
