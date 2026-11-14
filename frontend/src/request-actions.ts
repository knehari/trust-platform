import type { Application } from './RequestsPanel';

// Which action the console offers on one certificate request, from its
// recorded state and the token's roles. A display hint only: the API checks
// roles, grants and separation of duties on every write.
export interface RequestActions {
  canIssue: boolean;
  canAskRevocation: boolean;
  decideApplication: boolean;
  decideRevocation: boolean;
  proposeVoid: boolean;
  confirmVoid: boolean;
  /** Label of the button that opens the inline form, or null when none applies. */
  formLabel: string | null;
}

export function requestActions(item: Pick<Application, 'status' | 'open_revocation_id' | 'void_status' | 'void_proposed_by_reader'>,
  canRequest: boolean, canDecide: boolean): RequestActions {
  const canIssue = item.status === 'APPROVED' && (canRequest || canDecide);
  const canAskRevocation = item.status === 'ISSUED' && (canRequest || canDecide);
  const decideApplication = canDecide && item.status === 'SUBMITTED';
  const decideRevocation = canDecide && item.status === 'REVOCATION_REQUESTED' && Boolean(item.open_revocation_id);
  // Reconciliation (ADR-0020): one officer proposes, another confirms.
  const proposeVoid = canDecide && item.status === 'RECONCILIATION_REQUIRED' && !item.void_status;
  const confirmVoid = canDecide && item.status === 'RECONCILIATION_REQUIRED' && item.void_status === 'PROPOSED' && !item.void_proposed_by_reader;
  const formLabel = decideApplication ? 'Review' : decideRevocation ? 'Review revocation' : proposeVoid ? 'Reconcile…' : confirmVoid ? 'Review void'
    : canAskRevocation ? 'Revoke…' : null;
  return { canIssue, canAskRevocation, decideApplication, decideRevocation, proposeVoid, confirmVoid, formLabel };
}
