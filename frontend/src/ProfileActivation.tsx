import { useRef, useState } from 'react';
import { ApiError, apiPost, type ProfileDraft } from './api';

interface Props {
  caId: string;
  token: string;
  draft: ProfileDraft;
  onChanged: (status: ProfileDraft['status'], supersededRevision: number | null) => void;
  onUnauthorized: () => void;
}

/**
 * Activation of an APPROVED revision and retirement of the ACTIVE one by a CA
 * operator (ADR-0012). The server checks the operator's grant, that they did
 * not write, submit or decide on the revision, the exact digest, the CA's
 * policy version and declared suites. ACTIVE does not authorize issuance yet.
 */
export function ProfileActivation({ caId, token, draft, onChanged, onUnauthorized }: Props) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // One key per intended change, so a retry after a lost response is a replay.
  const key = useRef(crypto.randomUUID());
  const base = `/v1/cas/${encodeURIComponent(caId)}/profile-drafts/${encodeURIComponent(draft.profile_id)}/${draft.revision}`;

  async function send(action: 'activation' | 'retirement') {
    setBusy(true);
    setError(null);
    try {
      const result = await apiPost<{ status?: unknown; superseded_revision?: unknown }>(`${base}/${action}`, token,
        action === 'activation' ? { snapshot_sha256: draft.snapshot_sha256 } : {}, key.current);
      const status = result.value.status;
      const superseded = result.value.superseded_revision;
      if ((action === 'activation' ? status !== 'ACTIVE' : status !== 'RETIRED')
        || (superseded !== null && superseded !== undefined && !Number.isInteger(superseded))) {
        throw new Error('The management API returned an invalid lifecycle change.');
      }
      key.current = crypto.randomUUID();
      onChanged(status as ProfileDraft['status'], (superseded as number | null | undefined) ?? null);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
      else setError(failure instanceof ApiError && failure.status === 409
        ? 'The revision is no longer in a state that allows this change. Reload it.'
        : failure instanceof Error ? failure.message : 'Could not change the revision.');
    } finally {
      setBusy(false);
    }
  }

  if (draft.status !== 'APPROVED' && draft.status !== 'ACTIVE') return null;
  return <div className="subtle-panel profile-lifecycle-actions">
    <b>Operation</b>
    {draft.status === 'APPROVED' && <>
      <button type="button" disabled={busy} onClick={() => void send('activation')}>{busy ? 'Activating…' : 'Activate this revision'}</button>
      <p>Activation names this exact digest. The CA must use this revision's policy version and declare every proposed suite; any active revision of the profile is superseded. You cannot activate a revision you wrote, submitted or decided on.</p>
    </>}
    {draft.status === 'ACTIVE' && <>
      <button type="button" disabled={busy} onClick={() => void send('retirement')}>{busy ? 'Retiring…' : 'Retire this revision'}</button>
      <p>Retirement ends this revision; nothing replaces it until another approved revision is activated.</p>
    </>}
    {error && <p className="lookup-error" role="alert">{error}</p>}
    <p>No issuance path uses the active revision yet: activation does not authorize certificates.</p>
  </div>;
}
