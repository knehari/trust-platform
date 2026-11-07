import { useEffect, useRef, useState } from 'react';
import { ApiError, apiPost, type ProfileDraft } from './api';
import { parseProfileDraftForm, type ProfileDraftFields } from './profile-draft-form';
import { requireProfileDraft } from './profile-draft-validation';

interface Props {
  caId: string;
  token: string;
  initial: ProfileDraft | null;
  onCreated: (draft: ProfileDraft) => void;
  onUnauthorized: () => void;
  onClose: () => void;
}

/** Records a new immutable DRAFT revision. It approves and activates nothing. */
export function ProfileDraftForm({ caId, token, initial, onCreated, onUnauthorized, onClose }: Props) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [fields, setFields] = useState<ProfileDraftFields>({
    profileId: initial?.profile_id ?? '',
    displayName: initial?.display_name ?? '',
    policyVersion: initial?.policy_version ?? '',
    maxValidityDays: initial ? String(initial.max_validity_days) : '90',
    maxDnsSans: initial ? String(initial.max_dns_sans) : '5',
    zones: initial?.proposed_dns_zones.join(', ') ?? '',
    // A catalogue identifier, so the revision can later be activated on a
    // CA that declares it (ADR-0012).
    suites: initial?.proposed_signature_suites.join(', ') ?? 'ecdsa-p256-sha256',
  });
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  // One key per intended change: a retry after a lost response is a replay,
  // not a second revision. Editing a field starts a new change.
  const key = useRef(crypto.randomUUID());
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    return () => element?.close();
  }, []);
  function update(name: keyof ProfileDraftFields, value: string) {
    setFields(current => ({ ...current, [name]: value }));
    setError(null);
    key.current = crypto.randomUUID();
  }
  async function save() {
    const parsed = parseProfileDraftForm(fields);
    if ('error' in parsed) { setError(parsed.error); return; }
    setSaving(true);
    setError(null);
    try {
      const result = await apiPost<unknown>(`/v1/cas/${encodeURIComponent(caId)}/profile-drafts`, token, parsed.input, key.current);
      onCreated(requireProfileDraft(result.value, caId));
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onUnauthorized();
      else setError(failure instanceof Error ? failure.message : 'Could not record the revision.');
    } finally {
      setSaving(false);
    }
  }
  const input = (name: keyof ProfileDraftFields, label: string, props: Record<string, string> = {}) =>
    <label className="form-field" key={name}><span>{label}</span><input value={fields[name]} onChange={event => update(name, event.target.value)} {...props} /></label>;
  return <dialog ref={dialog} className="certificate-dialog" aria-labelledby="profile-draft-form-title" onClose={onClose}>
    <div className="dialog-heading"><div><div className="eyebrow">NEW REVISION</div><h2 id="profile-draft-form-title">Propose a profile revision</h2></div><button type="button" className="dialog-close" aria-label="Close revision form" onClick={() => dialog.current?.close()}><span aria-hidden="true">×</span></button></div>
    <form className="profile-draft-form" onSubmit={event => { event.preventDefault(); void save(); }}>
      {input('profileId', 'Profile ID', { autoComplete: 'off', spellCheck: 'false' })}
      {input('displayName', 'Display name')}
      {input('policyVersion', 'Policy version')}
      {input('maxValidityDays', 'Maximum validity (days)', { inputMode: 'numeric' })}
      {input('maxDnsSans', 'Maximum DNS SANs', { inputMode: 'numeric' })}
      {input('zones', 'Proposed DNS zones (comma or space separated)', { spellCheck: 'false' })}
      {input('suites', 'Proposed signature suites (comma or space separated)', { spellCheck: 'false' })}
      {error && <p className="lookup-error" role="alert">{error}</p>}
      <div className="form-actions"><button type="submit" disabled={saving}>{saving ? 'Recording…' : 'Record draft revision'}</button><button type="button" className="link-button" onClick={() => dialog.current?.close()}>Cancel</button></div>
    </form>
    <p className="dialog-note">The server assigns the next revision number. A recorded revision is immutable and inert: it is not approved, cannot be activated from here, and cannot authorize certificate issuance.</p>
  </dialog>;
}
