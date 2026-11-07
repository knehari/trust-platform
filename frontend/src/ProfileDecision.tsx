import { useRef, useState } from 'react';
import { ApiError, apiPost, type ProfileDraft } from './api';

interface Claim {
  decision: 'approve' | 'reject';
  claim: string;
  key_id: string;
  issued_at: string;
}

interface Props {
  caId: string;
  token: string;
  draft: ProfileDraft;
  onDecided: (status: ProfileDraft['status'], approvalCount: number) => void;
  onUnauthorized: () => void;
}

const CLAIM_PATTERN = /^trust-platform\/profile-decision\/v1;decision=(approve|reject);[^\r\n]{1,3900}$/u;

/**
 * Signed decision on a submitted revision (ADR-0011). The console never holds
 * a signing key: it shows the exact claim the server built, the approver
 * signs it with their own registered key outside the browser, and pastes the
 * signature. The server verifies it before recording anything.
 */
export function ProfileDecision({ caId, token, draft, onDecided, onUnauthorized }: Props) {
  const [claim, setClaim] = useState<Claim | null>(null);
  const [signature, setSignature] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState('');
  const recordKey = useRef('');
  const base = `/v1/cas/${encodeURIComponent(caId)}/profile-drafts/${encodeURIComponent(draft.profile_id)}/${draft.revision}`;

  async function prepare(decision: Claim['decision']) {
    setBusy(true);
    setError(null);
    setSignature('');
    setCopied('');
    try {
      // Preparing records nothing, so it needs no idempotency key; the
      // server still requires a JSON body.
      const response = await fetch(`${base}/decision-claims`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision }),
        credentials: 'omit',
        cache: 'no-store',
      });
      if (response.status === 401) { onUnauthorized(); return; }
      if (!response.ok) {
        throw new Error(response.status === 403 ? 'Your role, grant or key does not allow this decision, or you authored or submitted this revision.'
          : response.status === 409 ? 'This revision is no longer awaiting your decision.'
          : `Could not prepare the decision (${response.status}).`);
      }
      const value = await response.json() as Partial<Claim>;
      if (value.decision !== decision || typeof value.claim !== 'string' || !CLAIM_PATTERN.test(value.claim)
        || !value.claim.includes(`;decision=${decision};`) || !value.claim.includes(`;profile_id=${draft.profile_id};revision=${draft.revision};`)
        || !value.claim.includes(`;snapshot_sha256=${draft.snapshot_sha256};`)
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
      const result = await apiPost<{ status?: unknown; approval_count?: unknown }>(`${base}/decisions`, token,
        { decision: claim.decision, issued_at: claim.issued_at, signature_der_base64: encoded }, recordKey.current);
      const status = result.value.status;
      if ((status !== 'SUBMITTED' && status !== 'APPROVED' && status !== 'REJECTED') || typeof result.value.approval_count !== 'number') {
        throw new Error('The management API returned an invalid decision.');
      }
      setClaim(null);
      onDecided(status, result.value.approval_count);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
      else setError(failure instanceof ApiError && failure.status === 409
        ? 'The claim expired or the revision was decided meanwhile. Prepare the decision again.'
        : failure instanceof Error ? failure.message : 'Could not record the decision.');
    } finally {
      setBusy(false);
    }
  }

  async function copy(text: string, label: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(`${label} copied.`);
    } catch {
      setCopied(`Could not copy the ${label.toLowerCase()}; select it to copy manually.`);
    }
  }

  if (draft.status !== 'SUBMITTED') return null;
  const command = claim ? `printf '%s' '${claim.claim}' | openssl dgst -sha256 -sign .lab-keys/<your-approver-key>.pem | openssl base64 -A` : '';
  return <div className="subtle-panel profile-lifecycle-actions profile-decision">
    <b>Decision ({draft.approval_count}/2 approvals)</b>
    {!claim && <div className="form-actions">
      <button type="button" disabled={busy} onClick={() => void prepare('approve')}>Prepare approval</button>
      <button type="button" className="link-button" disabled={busy} onClick={() => void prepare('reject')}>Prepare rejection</button>
    </div>}
    {claim && <>
      <label className="form-field"><span>Claim to sign ({claim.decision}, key {claim.key_id}, valid 10 minutes)</span>
        <textarea readOnly rows={4} value={claim.claim} className="mono" /></label>
      <button type="button" className="link-button" onClick={() => void copy(claim.claim, 'Claim')}>Copy claim</button>
      <p>Sign the exact claim with your registered approver key, outside the browser. In the laboratory, from the repository:</p>
      <pre className="decision-command">{command}</pre>
      <button type="button" className="link-button" onClick={() => void copy(command, 'Command')}>Copy command</button>
      <label className="form-field"><span>Signature (base64, DER)</span>
        <textarea rows={3} value={signature} onChange={event => { setSignature(event.target.value); setError(null); }} spellCheck={false} /></label>
      <div className="form-actions">
        <button type="button" disabled={busy} onClick={() => void record()}>{busy ? 'Verifying…' : claim.decision === 'approve' ? 'Record approval' : 'Record rejection'}</button>
        <button type="button" className="link-button" disabled={busy} onClick={() => { setClaim(null); setError(null); }}>Cancel</button>
      </div>
    </>}
    {copied && <p role="status">{copied}</p>}
    {error && <p className="lookup-error" role="alert">{error}</p>}
    <p>Two different approvers with different registered keys must approve; one rejection ends the revision. The author and the submitter cannot decide. APPROVED does not activate the profile or authorize issuance.</p>
  </div>;
}
