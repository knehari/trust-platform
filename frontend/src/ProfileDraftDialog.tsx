import { useRef, useState } from 'react';
import { CopyJsonButton, DetailDrawer, DrawerSection, Fact } from './DetailDrawer';
import { Icon, Notice, StatusBadge, Tag } from './ui';
import { ApiError, apiPost, type ProfileDraft } from './api';
import { profileDraftMetadataJson } from './profile-draft-export';
import { ProfileDecision } from './ProfileDecision';
import { ProfileActivation } from './ProfileActivation';

interface SubmitAction {
  caId: string;
  token: string;
  onSubmitted: (submittedAt: string) => void;
  onUnauthorized: () => void;
  onProposeRevision: () => void;
}

interface DecisionAction {
  caId: string;
  token: string;
  onDecided: (status: ProfileDraft['status'], approvalCount: number) => void;
  onUnauthorized: () => void;
}

interface OperatorAction {
  caId: string;
  token: string;
  onChanged: (status: ProfileDraft['status'], supersededRevision: number | null) => void;
  onUnauthorized: () => void;
}

export function ProfileDraftDialog({ draft, onClose, onToggleComparison, comparisonSelected, editor, approver, operator }: { draft: ProfileDraft; onClose: () => void; onToggleComparison: () => void; comparisonSelected: boolean; editor: SubmitAction | null; approver: DecisionAction | null; operator: OperatorAction | null }) {
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
  const note = draft.status === 'SUBMITTED' ? 'This revision awaits approval. Submission is not approval: it cannot authorize certificate issuance.'
    : draft.status === 'APPROVED' ? 'Two approvers signed this exact revision. Approval does not activate it; a CA operator can.'
    : draft.status === 'ACTIVE' ? 'This is the active revision of the profile. Certificate requests are checked against it.'
    : draft.status === 'SUPERSEDED' ? 'A later revision of the profile was activated instead of this one.'
    : draft.status === 'RETIRED' ? 'This revision was retired. A change needs a new revision.'
    : draft.status === 'REJECTED' ? 'An approver rejected this revision. A change needs a new revision.'
    : 'This is an inert proposal. Syntax warnings are advisory; an empty warning list and the digest are neither approval nor authorization to issue certificates.';
  const date = (value: string | null | undefined) => value ? new Date(value).toLocaleString() : null;
  return <DetailDrawer labelledBy="profile-draft-dialog-title" eyebrow={`Profile proposal · ${draft.profile_id}`} icon="profile"
    tone={draft.status === 'REJECTED' ? 'bad' : draft.status === 'ACTIVE' || draft.status === 'APPROVED' ? 'good' : draft.status === 'SUBMITTED' ? 'info' : 'neutral'}
    closeLabel="Close proposal detail" onClose={onClose}
    title={`Revision ${draft.revision}`} subtitle={draft.display_name}
    badges={<><StatusBadge status={draft.status} />{draft.status !== 'DRAFT' && <span className="ui-chip">{draft.approval_count} of 2 approvals</span>}{draft.proposal_warnings.length > 0 && <Tag tone="warn">{draft.proposal_warnings.length} syntax warning{draft.proposal_warnings.length === 1 ? '' : 's'}</Tag>}</>}
    actions={<><CopyJsonButton json={profileDraftMetadataJson(draft)} label="Copy proposal metadata JSON" />
      <button type="button" className={comparisonSelected ? 'ui-button ui-button-ghost ui-button-sm ui-button-on' : 'ui-button ui-button-ghost ui-button-sm'} aria-pressed={comparisonSelected} onClick={onToggleComparison}>{comparisonSelected ? 'Remove from comparison' : 'Select for comparison'}</button></>}
    summary={<LifecycleStepper draft={draft} />}
    note={note}>
    {(editor || operator || approver) && <section className="ui-drawer-section ui-drawer-actions-panel"><h3>Your actions</h3>
      {editor && <div className="ui-stack">
        <div className="ui-actions">
          {draft.status === 'DRAFT' && <button type="button" className="ui-button ui-button-primary" disabled={submitting || draft.proposal_warnings.length > 0} onClick={() => void submitForApproval()}>{submitting ? 'Submitting…' : 'Submit for approval'}</button>}
          <button type="button" className="ui-button ui-button-secondary" onClick={editor.onProposeRevision}>Propose a new revision from this one</button>
        </div>
        {draft.status === 'DRAFT' && draft.proposal_warnings.length > 0 && <p className="ui-hint">Revisions with advisory syntax warnings cannot be submitted. Propose a corrected revision.</p>}
        {draft.status === 'DRAFT' && <p className="ui-hint">Only the latest revision of a profile can be submitted, with exactly the digest shown below. Submission does not approve or activate it.</p>}
        {submitError && <Notice tone="error" onDismiss={() => setSubmitError(null)}>{submitError}</Notice>}
      </div>}
      {operator && <ProfileActivation caId={operator.caId} token={operator.token} draft={draft} onChanged={operator.onChanged} onUnauthorized={operator.onUnauthorized} />}
      {approver && <ProfileDecision caId={approver.caId} token={approver.token} draft={draft} onDecided={approver.onDecided} onUnauthorized={approver.onUnauthorized} />}
    </section>}
    <DrawerSection title="Constraints">
      <Fact label="Policy version">{draft.policy_version}</Fact>
      <Fact label="Maximum validity">{draft.max_validity_days} days</Fact>
      <Fact label="Maximum DNS SANs">{draft.max_dns_sans}</Fact>
      <Fact label="Proposed DNS zones">{draft.proposed_dns_zones.length ? <span className="ui-chip-list">{draft.proposed_dns_zones.map(zone => <span key={zone} className="ui-chip">{zone}</span>)}</span> : 'None'}</Fact>
      <Fact label="Signature suites">{draft.proposed_signature_suites.length ? <span className="ui-chip-list">{draft.proposed_signature_suites.map(suite => <span key={suite} className="ui-chip">{suite}</span>)}</span> : 'None'}</Fact>
      <Fact label="Advisory syntax warnings">{draft.proposal_warnings.length ? <span className="ui-chip-list">{draft.proposal_warnings.map(warning => <Tag key={warning} tone="warn">{warning}</Tag>)}</span> : 'None recorded'}</Fact>
    </DrawerSection>
    <DrawerSection title="Integrity">
      <Fact label="Snapshot SHA-256" copy={draft.snapshot_sha256} mono>{draft.snapshot_sha256}</Fact>
      <Fact label="Profile ID" copy={draft.profile_id} mono>{draft.profile_id}</Fact>
    </DrawerSection>
    <DrawerSection title="History">
      <Fact label="Recorded">{date(draft.created_at)} · {draft.created_by}</Fact>
      {draft.submitted_at && <Fact label="Submitted for approval">{date(draft.submitted_at)}</Fact>}
      {draft.decided_at && <Fact label={draft.status === 'REJECTED' ? 'Rejected' : 'Approved'}>{date(draft.decided_at)}</Fact>}
      {draft.activated_at && <Fact label="Activated">{date(draft.activated_at)}</Fact>}
      {draft.ended_at && <Fact label={draft.status === 'RETIRED' ? 'Retired' : 'Superseded'}>{date(draft.ended_at)}</Fact>}
    </DrawerSection>
  </DetailDrawer>;
}

const STEPS = ['DRAFT', 'SUBMITTED', 'APPROVED', 'ACTIVE'] as const;

/** Where the revision stands in draft → submitted → approved → active, and how it ended. */
function LifecycleStepper({ draft }: { draft: ProfileDraft }) {
  const reached = draft.status === 'REJECTED' ? 1 : draft.status === 'RETIRED' || draft.status === 'SUPERSEDED' ? 3 : STEPS.indexOf(draft.status as typeof STEPS[number]);
  const ending = draft.status === 'REJECTED' ? 'Rejected' : draft.status === 'RETIRED' ? 'Retired' : draft.status === 'SUPERSEDED' ? 'Superseded' : null;
  return <div className="ui-stepper-wrap"><span className="ui-summary-label">Lifecycle</span>
    <ol className="ui-stepper" aria-label="Revision lifecycle">{STEPS.map((step, index) => {
      const state = index < reached ? 'done' : index === reached && !ending ? 'current' : index === reached && ending ? 'done' : 'todo';
      return <li key={step} className={`ui-step ${state}`} aria-current={state === 'current' ? 'step' : undefined}>
        <span className="ui-step-dot">{state === 'done' ? <Icon name="check" size={13} /> : index + 1}</span>
        <span className="ui-step-label">{step === 'DRAFT' ? 'Drafted' : step === 'SUBMITTED' ? 'Submitted' : step === 'APPROVED' ? 'Approved' : 'Active'}</span>
      </li>;
    })}{ending && <li className={`ui-step end ${draft.status === 'REJECTED' ? 'bad' : ''}`}><span className="ui-step-dot"><Icon name={draft.status === 'REJECTED' ? 'close' : 'check'} size={13} /></span><span className="ui-step-label">{ending}</span></li>}</ol>
  </div>;
}
