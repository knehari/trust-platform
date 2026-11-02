import { useEffect, useRef, useState } from 'react';
import { ApiError, apiPost, type ProfileDraft } from './api';
import { profileDraftMetadataJson } from './profile-draft-export';

interface SubmitAction {
  caId: string;
  token: string;
  onSubmitted: (submittedAt: string) => void;
  onUnauthorized: () => void;
  onProposeRevision: () => void;
}

export function ProfileDraftDialog({ draft, onClose, onToggleComparison, comparisonSelected, editor }: { draft: ProfileDraft; onClose: () => void; onToggleComparison: () => void; comparisonSelected: boolean; editor: SubmitAction | null }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [copyFeedback, setCopyFeedback] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  // Stable for this dialog: a retry of the same submission is a replay.
  const submitKey = useRef(crypto.randomUUID());
  async function submitForApproval() {
    if (!editor) return;
    setSubmitting(true);
    setSubmitError(null);
    try {
      const result = await apiPost<{ status?: unknown; submitted_at?: unknown }>(
        `/v1/cas/${encodeURIComponent(editor.caId)}/profile-drafts/${encodeURIComponent(draft.profile_id)}/${draft.revision}/submission`,
        editor.token, { snapshot_sha256: draft.snapshot_sha256 }, submitKey.current);
      if (result.value.status !== 'SUBMITTED' || typeof result.value.submitted_at !== 'string') throw new Error('The management API returned an invalid submission.');
      editor.onSubmitted(result.value.submitted_at);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) editor.onUnauthorized();
      else setSubmitError(failure instanceof Error ? failure.message : 'Could not submit this revision.');
    } finally {
      setSubmitting(false);
    }
  }
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    return () => element?.close();
  }, []);
  async function copyDigest() {
    try {
      await navigator.clipboard.writeText(draft.snapshot_sha256);
      setCopyFeedback('Snapshot digest copied.');
    } catch {
      setCopyFeedback('Could not copy the digest. Select it to copy manually.');
    }
  }
  async function copyMetadata() {
    try {
      await navigator.clipboard.writeText(profileDraftMetadataJson(draft));
      setCopyFeedback('Proposal metadata JSON copied.');
    } catch {
      setCopyFeedback('Could not copy proposal metadata.');
    }
  }
  const fields = [
    ['PROFILE ID', draft.profile_id],
    ['REVISION', String(draft.revision)],
    ['STATUS', draft.status],
    ...(draft.submitted_at ? [['SUBMITTED FOR APPROVAL', new Date(draft.submitted_at).toLocaleString()]] : []),
    ['DISPLAY NAME', draft.display_name],
    ['POLICY VERSION', draft.policy_version],
    ['MAXIMUM VALIDITY', `${draft.max_validity_days} days`],
    ['MAXIMUM DNS SANs', String(draft.max_dns_sans)],
    ['PROPOSED DNS ZONES', draft.proposed_dns_zones.join(', ') || 'None'],
    ['PROPOSED SIGNATURE SUITES', draft.proposed_signature_suites.join(', ') || 'None'],
    ['ADVISORY SYNTAX WARNINGS', draft.proposal_warnings.join(', ') || 'None recorded'],
    ['RECORDED BY', draft.created_by],
    ['RECORDED', new Date(draft.created_at).toLocaleString()],
  ];
  return <dialog ref={dialog} className="certificate-dialog" aria-labelledby="profile-draft-dialog-title" onClose={onClose}>
    <div className="dialog-heading"><div><div className="eyebrow">PROFILE PROPOSAL</div><h2 id="profile-draft-dialog-title">Revision {draft.revision}</h2></div><button type="button" className="dialog-close" aria-label="Close proposal detail" onClick={() => dialog.current?.close()}><span aria-hidden="true">×</span></button></div>
    <div className="detail-grid">{fields.map(([label, value]) => <div className="info-cell" key={label}><span>{label}</span><strong>{value}</strong></div>)}
      <div className="info-cell"><span>SNAPSHOT SHA-256</span><div className="metadata-value"><strong className="mono">{draft.snapshot_sha256}</strong><button type="button" className="link-button" onClick={() => void copyDigest()}>Copy</button></div></div>
    </div>
    {copyFeedback && <p className="copy-feedback" role="status">{copyFeedback}</p>}
    <button type="button" className="link-button profile-draft-action" onClick={() => void copyMetadata()}>Copy proposal metadata JSON</button>
    <button type="button" className="link-button profile-draft-action" aria-pressed={comparisonSelected} onClick={onToggleComparison}>{comparisonSelected ? 'Remove from comparison' : 'Select for comparison'}</button>
    {editor && <div className="subtle-panel profile-lifecycle-actions">
      {draft.status === 'DRAFT' && <button type="button" disabled={submitting || draft.proposal_warnings.length > 0} onClick={() => void submitForApproval()}>{submitting ? 'Submitting…' : 'Submit for approval'}</button>}
      <button type="button" className="link-button" onClick={editor.onProposeRevision}>Propose a new revision from this one</button>
      {draft.status === 'DRAFT' && draft.proposal_warnings.length > 0 && <p>Revisions with advisory syntax warnings cannot be submitted. Propose a corrected revision.</p>}
      {draft.status === 'DRAFT' && <p>Only the latest revision of a profile can be submitted, with exactly the digest shown above. Submission does not approve or activate it.</p>}
      {submitError && <p className="lookup-error" role="alert">{submitError}</p>}
    </div>}
    <p className="dialog-note">{draft.status === 'SUBMITTED' ? 'This revision awaits approval. Submission is not approval: it cannot authorize certificate issuance.' : 'This is an inert proposal. Syntax warnings are advisory; an empty warning list and the digest are neither approval nor authorization to issue certificates.'}</p>
  </dialog>;
}
