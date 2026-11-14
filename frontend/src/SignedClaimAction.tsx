import { useRef, useState } from 'react';
import { ApiError, apiPost } from './api';
import { signedClaimMatches, type ClaimKind, type ClaimSubject, type SignedClaim } from './signed-claim';

export interface ClaimChoice {
  /** Sent to the claims route (`decision`), and checked in the claim. */
  decision: string;
  /** Body for the claims route. */
  claimBody: unknown;
  prepareLabel: string;
  recordLabel: string;
  tone: 'primary' | 'danger' | 'secondary';
}

interface Props {
  token: string;
  kind: ClaimKind;
  subject: ClaimSubject;
  label: string;
  claimsPath: string;
  recordPath: string;
  choices: ClaimChoice[];
  reason: string;
  /** The recorded body, from the reason, the claim and the signature. */
  recordBody: (claim: SignedClaim, signature: string) => unknown;
  onDone: (claim: SignedClaim, value: unknown) => void;
  onError: (message: string) => void;
  onUnauthorized: () => void;
  onCancel: () => void;
}

/**
 * Signs a revocation decision or a void confirmation (ADR-0029). As for
 * certificate decisions, the console never holds a key: it shows the claim the
 * server built, the officer signs it outside the browser, and pastes the
 * signature. The signer verifies it again before it lists the serial on a CRL.
 */
export function SignedClaimAction(props: Props) {
  const { token, kind, subject, label, claimsPath, recordPath, choices, reason } = props;
  const [claim, setClaim] = useState<SignedClaim | null>(null);
  const [signature, setSignature] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const recordKey = useRef('');

  async function prepare(choice: ClaimChoice) {
    setBusy(true);
    setError(null);
    setSignature('');
    try {
      const response = await fetch(claimsPath, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify(choice.claimBody),
        credentials: 'omit',
        cache: 'no-store',
      });
      if (response.status === 401) { props.onUnauthorized(); return; }
      if (!response.ok) {
        throw new Error(response.status === 403 ? 'Your role, grant or registered officer key does not allow this.'
          : response.status === 404 ? 'Nothing to decide on for this request any more.'
          : `Could not prepare the claim (${response.status}).`);
      }
      const value = await response.json() as Partial<SignedClaim>;
      if (!signedClaimMatches(value, kind, choice.decision, subject)) throw new Error('The management API returned an invalid claim.');
      recordKey.current = crypto.randomUUID();
      setClaim(value);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Could not prepare the claim.');
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
      const result = await apiPost(recordPath, token, props.recordBody(claim, encoded), recordKey.current);
      const done = claim;
      setClaim(null);
      props.onDone(done, result.value);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) props.onUnauthorized();
      else if (failure instanceof ApiError && failure.status === 422) setError('The signature does not verify with your registered key over this exact claim. Nothing was recorded.');
      else if (failure instanceof ApiError && failure.status === 409) setError('The claim expired or the request was decided meanwhile. Prepare it again.');
      else if (failure instanceof ApiError && failure.status === 403) props.onError('Could not record it: you asked for this revocation or proposed this void, or your grant changed.');
      else setError(failure instanceof Error ? failure.message : 'Could not record the decision.');
    } finally {
      setBusy(false);
    }
  }

  const choice = claim ? choices.find(item => item.decision === claim.decision) : undefined;
  if (!claim) {
    return <>
      {choices.map(item => <button key={item.decision} type="button" className={`ui-button ui-button-sm ui-button-${item.tone}`}
        disabled={busy || !reason.trim()} onClick={() => void prepare(item)}>{item.prepareLabel}</button>)}
      <button type="button" className="ui-button ui-button-ghost ui-button-sm" onClick={props.onCancel}>Cancel</button>
      {error && <p className="lookup-error" role="alert">{error}</p>}
    </>;
  }
  const command = `printf '%s' '${claim.claim}' | openssl dgst -sha256 -sign .lab-keys/<your-officer-key>.pem | openssl base64 -A`;
  return <div className="ui-stack application-decision">
    <label className="ui-field ui-field-wide"><span>Claim to sign (key {claim.key_id}, valid 10 minutes)</span>
      <textarea readOnly rows={3} value={claim.claim} className="mono" aria-label={`${label} claim`} /></label>
    <p className="ui-hint">Sign the exact claim with your registered officer key, outside the browser. The signer checks this signature again before it lists the serial on a CRL. In the laboratory, from the repository:</p>
    <pre className="decision-command">{command}</pre>
    <label className="ui-field ui-field-wide"><span>Signature (base64, DER)</span>
      <textarea rows={3} value={signature} aria-label={`${label} signature`} spellCheck={false}
        onChange={event => { setSignature(event.target.value); setError(null); }} /></label>
    <div className="ui-actions">
      <button type="button" className={`ui-button ui-button-sm ui-button-${choice?.tone ?? 'primary'}`} disabled={busy} onClick={() => void record()}>
        {busy ? 'Verifying…' : choice?.recordLabel ?? 'Record'}</button>
      <button type="button" className="ui-button ui-button-ghost ui-button-sm" disabled={busy} onClick={() => { setClaim(null); setError(null); }}>Back</button>
    </div>
    {error && <p className="lookup-error" role="alert">{error}</p>}
  </div>;
}
