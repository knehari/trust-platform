#!/usr/bin/env bash
set -euo pipefail

# Run only against a disposable ledgered source and an empty target database.
: "${TRUST_RESTORE_SOURCE_URL:?set TRUST_RESTORE_SOURCE_URL to the ledgered fixture}"
: "${TRUST_RESTORE_TARGET_URL:?set TRUST_RESTORE_TARGET_URL to an empty database}"
psql_bin=${TRUST_PSQL_BIN:-psql}
runner=${TRUST_LEDGER_BIN:-target/debug/lab_migrate_management}

source_versions=$("$psql_bin" "$TRUST_RESTORE_SOURCE_URL" -XAt -v ON_ERROR_STOP=1 \
  -c "SELECT string_agg(version, ',' ORDER BY version) FROM management_migration_ledger")
if [[ "$source_versions" != '0012_management_read_views,0013_management_reader_grants,0014_certificate_subject_cn,0015_verified_certificate_metadata,0016_profile_draft_catalogue,0017_management_history_window,0018_management_certificate_san,0019_management_certificate_cn_lower,0020_management_history_bounds,0021_management_reader_isolation' ]]; then
  echo 'Restore source lacks the complete 0012–0021 migration ledger' >&2
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
   [[ "$run_output" == *'APPLY:'* ]]; then
  echo 'Restored migration ledger was not recognized without reapplication' >&2
  echo "$run_output" >&2
  exit 1
fi
echo 'PASS: restored ledger matches source and prevents migration reapplication'
