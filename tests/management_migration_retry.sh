#!/usr/bin/env bash
set -euo pipefail

# Apply the existing files verbatim to a new, disposable PostgreSQL database.
: "${TRUST_UPGRADE_DATABASE_URL:?set TRUST_UPGRADE_DATABASE_URL to an empty disposable database}"
psql_bin=${TRUST_PSQL_BIN:-psql}
database_url=$TRUST_UPGRADE_DATABASE_URL
initial_relations=$("$psql_bin" "$database_url" -XAt -v ON_ERROR_STOP=1 \
  -c "SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r','p','v','m','S')")
if [[ "$initial_relations" != 0 ]]; then
  echo 'Migration retry target must have no public relations' >&2
  exit 1
fi

for migration in migrations/000*.sql migrations/0010*.sql migrations/0011*.sql; do
  "$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 -f "$migration" >/dev/null
done
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f tests/management_populated_upgrade_seed.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0012_management_read_views.sql >/dev/null

core_before=$("$psql_bin" "$database_url" -XAt -v ON_ERROR_STOP=1 \
  -f tests/management_migration_core_fingerprint.sql)
test -n "$core_before"

"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f tests/management_migration_fault.sql >/dev/null
cleanup() {
  "$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
    -c 'DROP EVENT TRIGGER IF EXISTS management_migration_fault; DROP FUNCTION IF EXISTS management_migration_fault()' >/dev/null
}
trap cleanup EXIT

if output=$("$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
    -f migrations/0013_management_reader_grants.sql 2>&1); then
  echo 'Migration 0013 unexpectedly succeeded with the fault trigger active' >&2
  exit 1
fi
if [[ "$output" != *'intentional lab migration fault'* ]]; then
  echo 'Migration failed for a reason other than the injected fault' >&2
  echo "$output" >&2
  exit 1
fi

partial_state=$("$psql_bin" "$database_url" -XAt -v ON_ERROR_STOP=1 -c "
  SELECT to_regclass('public.management_ca') IS NOT NULL,
         to_regclass('public.management_reader_grant') IS NULL,
         to_regclass('public.management_reader_scope') IS NULL")
if [[ "$partial_state" != 't|t|t' ]]; then
  echo "Unexpected schema after failed 0013: $partial_state" >&2
  exit 1
fi
core_after_failure=$("$psql_bin" "$database_url" -XAt -v ON_ERROR_STOP=1 \
  -f tests/management_migration_core_fingerprint.sql)
if [[ "$core_after_failure" != "$core_before" ]]; then
  echo 'Pre-existing rows changed during failed 0013' >&2
  exit 1
fi
echo 'PASS: failed 0013 rolled back while 0012 and existing rows survived'

cleanup
trap - EXIT
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0013_management_reader_grants.sql >/dev/null
core_after_retry=$("$psql_bin" "$database_url" -XAt -v ON_ERROR_STOP=1 \
  -f tests/management_migration_core_fingerprint.sql)
if [[ "$core_after_retry" != "$core_before" ]]; then
  echo 'Pre-existing rows changed during 0013 retry' >&2
  exit 1
fi
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0014_certificate_subject_cn.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0015_verified_certificate_metadata.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0016_profile_draft_catalogue.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0017_management_history_window.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0018_management_certificate_san.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0019_management_certificate_cn_lower.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0020_management_history_bounds.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0021_management_reader_isolation.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0022_profile_draft_submission.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0023_profile_draft_decision.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0024_profile_revision_activation.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0025_profile_draft_revision_sequence.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0026_ca_proposal.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0027_ca_approval_activation.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0028_ca_suspension_retirement.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0029_certificate_application.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0030_application_issuance.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0031_revocation_crl.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0032_crl_publication.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0033_management_certificate_revocation.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0034_application_issuance_void.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0035_crl_auto_renewal.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0036_audit_event_chain.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0037_audit_chain_checkpoint.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0038_ra_issuance_channel.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0039_ra_revocation_channel.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0040_crl_publish_on_revocation.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0041_signer_authorization_proofs.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0042_signed_revocation_proofs.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0043_separate_crl_publication.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0044_dedicated_worker.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0045_operational_metrics.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0046_ra_hardening.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f migrations/0047_ra_key_rotation.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f tests/management_populated_upgrade_verify.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f tests/management_api_readonly.sql >/dev/null
echo 'PASS: 0013 retry preserved rows, views and reader privileges'
