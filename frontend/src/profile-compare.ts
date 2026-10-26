import type { ProfileDraft } from './api';
import { csv } from './selected-csv.ts';

export interface ProfileDifference {
  label: string;
  before: string;
  after: string;
  changed: boolean;
}

export function compareProfileRevisions(first: ProfileDraft, second: ProfileDraft): ProfileDifference[] {
  if (first.ca_id !== second.ca_id || first.profile_id !== second.profile_id || first.revision === second.revision
    || first.status !== 'DRAFT' || second.status !== 'DRAFT') {
    throw new Error('Select two different draft revisions of the same profile and authority.');
  }
  const [before, after] = first.revision < second.revision ? [first, second] : [second, first];
  const rows: [string, string, string][] = [
    ['Revision', String(before.revision), String(after.revision)],
    ['Display name', before.display_name, after.display_name],
    ['Policy version', before.policy_version, after.policy_version],
    ['Maximum validity days', String(before.max_validity_days), String(after.max_validity_days)],
    ['Maximum DNS SANs', String(before.max_dns_sans), String(after.max_dns_sans)],
    ['Proposed DNS zones', JSON.stringify(before.proposed_dns_zones), JSON.stringify(after.proposed_dns_zones)],
    ['Proposed signature suites', JSON.stringify(before.proposed_signature_suites), JSON.stringify(after.proposed_signature_suites)],
    ['Advisory syntax warnings', JSON.stringify(before.proposal_warnings), JSON.stringify(after.proposal_warnings)],
    ['Snapshot SHA-256', before.snapshot_sha256, after.snapshot_sha256],
  ];
  return rows.map(([label, oldValue, newValue]) => ({ label, before: oldValue, after: newValue, changed: oldValue !== newValue }));
}

export function profileComparisonCsv(first: ProfileDraft, second: ProfileDraft, changesOnly: boolean): string {
  const [earlier, later] = first.revision < second.revision ? [first, second] : [second, first];
  const differences = compareProfileRevisions(first, second);
  return csv(
    ['ca_id', 'profile_id', 'earlier_revision', 'later_revision', 'field', 'earlier_value', 'later_value', 'changed'],
    (changesOnly ? differences.filter(row => row.changed) : differences).map(row => [
      first.ca_id, first.profile_id, String(earlier.revision), String(later.revision),
      row.label, row.before, row.after, row.changed ? 'yes' : 'no',
    ]),
  );
}
