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
  -f tests/management_populated_upgrade_verify.sql >/dev/null
"$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
  -f tests/management_api_readonly.sql >/dev/null
echo 'PASS: 0013 retry preserved rows, views and reader privileges'
