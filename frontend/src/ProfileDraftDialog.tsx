import { useEffect, useRef, useState } from 'react';
import type { ProfileDraft } from './api';
import { profileDraftMetadataJson } from './profile-draft-export';

export function ProfileDraftDialog({ draft, onClose, onToggleComparison, comparisonSelected }: { draft: ProfileDraft; onClose: () => void; onToggleComparison: () => void; comparisonSelected: boolean }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [copyFeedback, setCopyFeedback] = useState('');
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
    <p className="dialog-note">This is an inert proposal. Syntax warnings are advisory; an empty warning list and the digest are neither approval nor authorization to issue certificates.</p>
  </dialog>;
}
