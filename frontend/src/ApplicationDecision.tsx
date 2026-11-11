import { useRef, useState } from 'react';
import { ApiError, apiPost } from './api';
import { claimMatches, type ApplicationClaim, type ClaimedApplication } from './application-claim';

type Claim = ApplicationClaim;

interface Props {
  caId: string;
  token: string;
  item: ClaimedApplication;
  reason: string;
  onDecided: (message: string) => void;
  onError: (message: string) => void;
  onUnauthorized: () => void;
  onCancel: () => void;
}

/**
 * Signed decision on a certificate request (ADR-0028). As for profiles, the
 * console never holds a key: it shows the claim the server built, the
 * officer signs it outside the browser with their registered key, and pastes
 * the signature. The laboratory signer verifies that signature again before
 * it signs the certificate.
 */
export function ApplicationDecision({ caId, token, item, reason, onDecided, onError, onUnauthorized, onCancel }: Props) {
  const [claim, setClaim] = useState<Claim | null>(null);
  const [signature, setSignature] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState('');
  const recordKey = useRef('');
  const base = `/v1/cas/${encodeURIComponent(caId)}/certificate-applications/${encodeURIComponent(item.application_id)}`;

  async function prepare(decision: Claim['decision']) {
    setBusy(true);
    setError(null);
    setSignature('');
    setCopied('');
    try {
      // Preparing records nothing, so it needs no idempotency key.
      const response = await fetch(`${base}/decision-claims`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision }),
        credentials: 'omit',
        cache: 'no-store',
      });
      if (response.status === 401) { onUnauthorized(); return; }
      if (!response.ok) {
        throw new Error(response.status === 403 ? 'Your role, grant or registered officer key does not allow this decision.'
          : response.status === 404 ? 'This request no longer exists for this authority.'
          : `Could not prepare the decision (${response.status}).`);
      }
      const value = await response.json() as Partial<Claim>;
      if (!claimMatches(value, decision, caId, item)) throw new Error('The management API returned an invalid decision claim.');
      recordKey.current = crypto.randomUUID();
      setClaim(value);
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
      await apiPost(`${base}/decision`, token,
        { decision: claim.decision, reason: reason.trim(), issued_at: claim.issued_at, signature_der_base64: encoded }, recordKey.current);
      setClaim(null);
      onDecided(claim.decision === 'approve' ? `Request for ${item.subject_cn} approved with your signed decision.` : `Request for ${item.subject_cn} rejected.`);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
      else if (failure instanceof ApiError && failure.status === 422) setError('The signature does not verify with your registered key over this exact claim. Nothing was recorded.');
      else if (failure instanceof ApiError && failure.status === 409) setError('The claim expired or the request was decided meanwhile. Prepare the decision again.');
      else if (failure instanceof ApiError && failure.status === 403) onError('Could not record the decision: you cannot decide on a request you made, or your grant changed.');
      else setError(failure instanceof Error ? failure.message : 'Could not record the decision.');
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

  const command = claim ? `printf '%s' '${claim.claim}' | openssl dgst -sha256 -sign .lab-keys/<your-officer-key>.pem | openssl base64 -A` : '';
  if (!claim) {
    return <>
      <button type="button" className="ui-button ui-button-primary ui-button-sm" disabled={busy || !reason.trim()} onClick={() => void prepare('approve')}>Prepare approval</button>
      <button type="button" className="ui-button ui-button-danger ui-button-sm" disabled={busy || !reason.trim()} onClick={() => void prepare('reject')}>Prepare rejection</button>
      <button type="button" className="ui-button ui-button-ghost ui-button-sm" onClick={onCancel}>Cancel</button>
      {error && <p className="lookup-error" role="alert">{error}</p>}
    </>;
  }
  return <div className="ui-stack application-decision">
    <label className="ui-field ui-field-wide"><span>Claim to sign ({claim.decision}, key {claim.key_id}, valid 10 minutes)</span>
      <textarea readOnly rows={4} value={claim.claim} className="mono" aria-label={`Decision claim for ${item.subject_cn}`} /></label>
    <p className="ui-hint">Sign the exact claim with your registered officer key, outside the browser. The signer checks this signature again before it signs the certificate. In the laboratory, from the repository:</p>
    <pre className="decision-command">{command}</pre>
    <div className="ui-actions">
      <button type="button" className="ui-button ui-button-secondary ui-button-sm" onClick={() => void copy(claim.claim, 'Claim')}>Copy claim</button>
      <button type="button" className="ui-button ui-button-secondary ui-button-sm" onClick={() => void copy(command, 'Command')}>Copy command</button>
    </div>
    <label className="ui-field ui-field-wide"><span>Signature (base64, DER)</span>
      <textarea rows={3} value={signature} aria-label={`Decision signature for ${item.subject_cn}`} spellCheck={false}
        onChange={event => { setSignature(event.target.value); setError(null); }} /></label>
    <div className="ui-actions">
      <button type="button" className={`ui-button ui-button-sm ${claim.decision === 'approve' ? 'ui-button-primary' : 'ui-button-danger'}`} disabled={busy} onClick={() => void record()}>
        {busy ? 'Verifying…' : claim.decision === 'approve' ? 'Record approval' : 'Record rejection'}</button>
      <button type="button" className="ui-button ui-button-ghost ui-button-sm" disabled={busy} onClick={() => { setClaim(null); setError(null); }}>Back</button>
    </div>
    {copied && <p role="status" className="ui-hint">{copied}</p>}
    {error && <p className="lookup-error" role="alert">{error}</p>}
  </div>;
}
