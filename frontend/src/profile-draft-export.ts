import type { ProfileDraft } from './api';

export function profileDraftMetadataJson(draft: ProfileDraft): string {
  return JSON.stringify({
    kind: 'trust-profile-proposal-metadata',
    ca_id: draft.ca_id,
    profile_id: draft.profile_id,
    revision: draft.revision,
    status: draft.status,
    display_name: draft.display_name,
    policy_version: draft.policy_version,
    max_validity_days: draft.max_validity_days,
    max_dns_sans: draft.max_dns_sans,
    proposed_dns_zones: draft.proposed_dns_zones,
    proposed_signature_suites: draft.proposed_signature_suites,
    advisory_syntax_warnings: draft.proposal_warnings,
    snapshot_sha256: draft.snapshot_sha256,
    recorded_at: draft.created_at,
  }, null, 2);
}
