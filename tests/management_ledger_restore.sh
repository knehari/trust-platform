#!/usr/bin/env bash
set -euo pipefail

# Run only against a disposable ledgered source and an empty target database.
: "${TRUST_RESTORE_SOURCE_URL:?set TRUST_RESTORE_SOURCE_URL to the ledgered fixture}"
: "${TRUST_RESTORE_TARGET_URL:?set TRUST_RESTORE_TARGET_URL to an empty database}"
psql_bin=${TRUST_PSQL_BIN:-psql}
runner=${TRUST_LEDGER_BIN:-target/debug/lab_migrate_management}

source_versions=$("$psql_bin" "$TRUST_RESTORE_SOURCE_URL" -XAt -v ON_ERROR_STOP=1 \
  -c "SELECT string_agg(version, ',' ORDER BY version) FROM management_migration_ledger")
if [[ "$source_versions" != '0012_management_read_views,0013_management_reader_grants,0014_certificate_subject_cn,0015_verified_certificate_metadata,0016_profile_draft_catalogue,0017_management_history_window,0018_management_certificate_san,0019_management_certificate_cn_lower,0020_management_history_bounds,0021_management_reader_isolation,0022_profile_draft_submission,0023_profile_draft_decision,0024_profile_revision_activation,0025_profile_draft_revision_sequence,0026_ca_proposal,0027_ca_approval_activation,0028_ca_suspension_retirement,0029_certificate_application,0030_application_issuance,0031_revocation_crl,0032_crl_publication,0033_management_certificate_revocation,0034_application_issuance_void,0035_crl_auto_renewal,0036_audit_event_chain,0037_audit_chain_checkpoint,0038_ra_issuance_channel,0039_ra_revocation_channel,0040_crl_publish_on_revocation,0041_signer_authorization_proofs,0042_signed_revocation_proofs,0043_separate_crl_publication,0044_dedicated_worker,0045_operational_metrics,0046_ra_hardening,0047_ra_key_rotation,0048_short_lived_certificates,0049_ra_policy_views' ]]; then
  echo 'Restore source lacks the complete 0012–0049 migration ledger' >&2
  exit 1
fi

bash tests/management_dump_restore.sh

run_output=$(TRUST_MIGRATION_DATABASE_URL="$TRUST_RESTORE_TARGET_URL" "$runner")
if [[ "$run_output" != *'SKIP: 0012_management_read_views already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0013_management_reader_grants already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0014_certificate_subject_cn already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0015_verified_certificate_metadata already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0016_profile_draft_catalogue already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0017_management_history_window already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0018_management_certificate_san already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0019_management_certificate_cn_lower already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0020_management_history_bounds already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0021_management_reader_isolation already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0022_profile_draft_submission already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0023_profile_draft_decision already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0024_profile_revision_activation already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0025_profile_draft_revision_sequence already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0026_ca_proposal already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0027_ca_approval_activation already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0028_ca_suspension_retirement already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0029_certificate_application already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0030_application_issuance already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0031_revocation_crl already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0032_crl_publication already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0033_management_certificate_revocation already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0034_application_issuance_void already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0035_crl_auto_renewal already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0036_audit_event_chain already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0037_audit_chain_checkpoint already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0038_ra_issuance_channel already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0039_ra_revocation_channel already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0040_crl_publish_on_revocation already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0041_signer_authorization_proofs already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0042_signed_revocation_proofs already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0043_separate_crl_publication already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0044_dedicated_worker already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0045_operational_metrics already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0046_ra_hardening already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0047_ra_key_rotation already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0048_short_lived_certificates already recorded with matching checksum'* ]] ||
   [[ "$run_output" != *'SKIP: 0049_ra_policy_views already recorded with matching checksum'* ]] ||
   [[ "$run_output" == *'APPLY:'* ]]; then
  echo 'Restored migration ledger was not recognized without reapplication' >&2
  echo "$run_output" >&2
  exit 1
fi
echo 'PASS: restored ledger matches source and prevents migration reapplication'
