#!/usr/bin/env bash
set -euo pipefail

# All URLs must name disposable PostgreSQL databases owned by the lab operator.
: "${TRUST_LEDGER_DATABASE_URL:?set TRUST_LEDGER_DATABASE_URL to an empty database}"
: "${TRUST_LEDGER_FAULT_DATABASE_URL:?set TRUST_LEDGER_FAULT_DATABASE_URL to an empty database}"
: "${TRUST_LEDGER_UNTRACKED_URL:?set TRUST_LEDGER_UNTRACKED_URL to a manually migrated fixture}"
psql_bin=${TRUST_PSQL_BIN:-psql}
runner=${TRUST_LEDGER_BIN:-target/debug/lab_migrate_management}

prepare() {
  local database_url=$1
  local count
  count=$("$psql_bin" "$database_url" -XAt -v ON_ERROR_STOP=1 \
    -c "SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r','p','v','m','S')")
  if [[ "$count" != 0 ]]; then
    echo 'Migration ledger test requires empty databases' >&2
    exit 1
  fi
  for migration in migrations/000*.sql migrations/0010*.sql migrations/0011*.sql; do
    "$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 -f "$migration" >/dev/null
  done
  "$psql_bin" "$database_url" -X -v ON_ERROR_STOP=1 \
    -f tests/management_populated_upgrade_seed.sql >/dev/null
}

run_migration() {
  TRUST_MIGRATION_DATABASE_URL=$1 "$runner"
}

expect_failure() {
  local database_url=$1
  local expected=$2
  local output
  if output=$(run_migration "$database_url" 2>&1); then
    echo "Migration runner unexpectedly succeeded: $expected" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    echo "Migration runner failed for an unexpected reason: $output" >&2
    exit 1
  fi
}

prepare "$TRUST_LEDGER_DATABASE_URL"
prepare "$TRUST_LEDGER_FAULT_DATABASE_URL"
core_before=$("$psql_bin" "$TRUST_LEDGER_DATABASE_URL" -XAt -v ON_ERROR_STOP=1 \
  -f tests/management_migration_core_fingerprint.sql)
test -n "$core_before"

umask 077
logs=$(mktemp -d "${TMPDIR:-/tmp}/trust-migration-ledger.XXXXXX")
trap 'rm -rf "$logs"' EXIT
run_migration "$TRUST_LEDGER_DATABASE_URL" >"$logs/first" 2>&1 &
first_pid=$!
run_migration "$TRUST_LEDGER_DATABASE_URL" >"$logs/second" 2>&1 &
second_pid=$!
first_status=0
second_status=0
wait "$first_pid" || first_status=$?
wait "$second_pid" || second_status=$?
if [[ "$first_status" != 0 || "$second_status" != 0 ]]; then
  echo 'Concurrent migration runner failed:' >&2
  cat "$logs/first" "$logs/second" >&2
  exit 1
fi
if [[ $(grep -hc '^APPLY:' "$logs/first" "$logs/second" | awk '{s+=$1} END {print s}') != 4 ]] ||
   [[ $(grep -hc '^SKIP:' "$logs/first" "$logs/second" | awk '{s+=$1} END {print s}') != 4 ]]; then
  echo 'Concurrent runners did not apply each migration exactly once' >&2
  cat "$logs/first" "$logs/second" >&2
  exit 1
fi
ledger_count=$("$psql_bin" "$TRUST_LEDGER_DATABASE_URL" -XAt -v ON_ERROR_STOP=1 \
  -c 'SELECT count(*) FROM management_migration_ledger')
test "$ledger_count" = 4
core_after=$("$psql_bin" "$TRUST_LEDGER_DATABASE_URL" -XAt -v ON_ERROR_STOP=1 \
  -f tests/management_migration_core_fingerprint.sql)
test "$core_after" = "$core_before"
"$psql_bin" "$TRUST_LEDGER_DATABASE_URL" -X -v ON_ERROR_STOP=1 \
  -f tests/management_populated_upgrade_verify.sql >/dev/null
"$psql_bin" "$TRUST_LEDGER_DATABASE_URL" -X -v ON_ERROR_STOP=1 \
  -f tests/management_api_readonly.sql >/dev/null
if reader_output=$("$psql_bin" "$TRUST_LEDGER_DATABASE_URL" -X -v ON_ERROR_STOP=1 \
  -c 'SET ROLE trust_api_reader; SELECT count(*) FROM management_migration_ledger' 2>&1); then
  echo 'Restricted API reader unexpectedly read the migration ledger' >&2
  exit 1
fi
[[ "$reader_output" == *'permission denied for table management_migration_ledger'* ]]
run_migration "$TRUST_LEDGER_DATABASE_URL" >"$logs/repeated"
test "$(grep -c '^SKIP:' "$logs/repeated")" = 4
echo 'PASS: concurrent and repeated migration runs recorded 0012–0015 once'

original_checksum=$("$psql_bin" "$TRUST_LEDGER_DATABASE_URL" -XAt -v ON_ERROR_STOP=1 \
  -c "SELECT source_sha256 FROM management_migration_ledger WHERE version = '0013_management_reader_grants'")
test "${#original_checksum}" = 64
"$psql_bin" "$TRUST_LEDGER_DATABASE_URL" -X -v ON_ERROR_STOP=1 \
  -c "UPDATE management_migration_ledger SET source_sha256 = repeat('0',64) WHERE version = '0013_management_reader_grants'" >/dev/null
expect_failure "$TRUST_LEDGER_DATABASE_URL" 'checksum drift'
"$psql_bin" "$TRUST_LEDGER_DATABASE_URL" -X -v ON_ERROR_STOP=1 \
  -c "UPDATE management_migration_ledger SET source_sha256 = '$original_checksum' WHERE version = '0013_management_reader_grants'" >/dev/null
"$psql_bin" "$TRUST_LEDGER_DATABASE_URL" -X -v ON_ERROR_STOP=1 \
  -c 'DROP VIEW management_audit' >/dev/null
expect_failure "$TRUST_LEDGER_DATABASE_URL" 'recorded 0012_management_read_views schema missing'
echo 'PASS: ledger refuses checksum drift and missing recorded schema'

"$psql_bin" "$TRUST_LEDGER_FAULT_DATABASE_URL" -X -v ON_ERROR_STOP=1 \
  -f tests/management_migration_fault.sql >/dev/null
expect_failure "$TRUST_LEDGER_FAULT_DATABASE_URL" 'intentional lab migration fault'
fault_state=$("$psql_bin" "$TRUST_LEDGER_FAULT_DATABASE_URL" -XAt -v ON_ERROR_STOP=1 -c "
  SELECT (SELECT count(*) FROM management_migration_ledger),
         to_regclass('public.management_ca') IS NOT NULL,
         to_regclass('public.management_reader_grant') IS NULL")
test "$fault_state" = '1|t|t'
"$psql_bin" "$TRUST_LEDGER_FAULT_DATABASE_URL" -X -v ON_ERROR_STOP=1 \
  -c 'DROP EVENT TRIGGER management_migration_fault; DROP FUNCTION management_migration_fault()' >/dev/null
run_migration "$TRUST_LEDGER_FAULT_DATABASE_URL" >"$logs/resumed"
grep -q '^SKIP: 0012_management_read_views' "$logs/resumed"
grep -q '^APPLY: 0013_management_reader_grants' "$logs/resumed"
"$psql_bin" "$TRUST_LEDGER_FAULT_DATABASE_URL" -X -v ON_ERROR_STOP=1 \
  -f tests/management_populated_upgrade_verify.sql >/dev/null
"$psql_bin" "$TRUST_LEDGER_FAULT_DATABASE_URL" -X -v ON_ERROR_STOP=1 \
  -f tests/management_api_readonly.sql >/dev/null
echo 'PASS: interrupted 0013 left one ledger row and resumed safely'

expect_failure "$TRUST_LEDGER_UNTRACKED_URL" 'untracked management schema'
untracked_ledger=$("$psql_bin" "$TRUST_LEDGER_UNTRACKED_URL" -XAt -v ON_ERROR_STOP=1 \
  -c "SELECT to_regclass('public.management_migration_ledger') IS NULL")
test "$untracked_ledger" = t
echo 'PASS: runner refuses existing management schema without a ledger'
