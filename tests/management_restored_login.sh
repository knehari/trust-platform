#!/usr/bin/env bash
set -euo pipefail

# Run only against the disposable restored fixture. The login is provisioned
# separately so this checks a real PostgreSQL login, not SET ROLE by its owner.
: "${TRUST_RESTORE_ADMIN_URL:?set TRUST_RESTORE_ADMIN_URL}"
: "${TRUST_RESTORE_READER_URL:?set TRUST_RESTORE_READER_URL}"
psql_bin=${TRUST_PSQL_BIN:-psql}

expect_denied() {
  local query=$1
  local description=$2
  local output
  if output=$("$psql_bin" "$TRUST_RESTORE_READER_URL" -XAt -v ON_ERROR_STOP=1 \
      -c "$query" 2>&1); then
    echo "Reader login unexpectedly allowed $description" >&2
    exit 1
  fi
  if [[ "$output" != *'permission denied'* ]]; then
    echo "Reader login failed for an unexpected reason while checking $description" >&2
    echo "$output" >&2
    exit 1
  fi
}

cleanup() {
  "$psql_bin" "$TRUST_RESTORE_ADMIN_URL" -X -v ON_ERROR_STOP=1 \
    -c 'REVOKE trust_api_reader FROM trust_restore_login_ci' >/dev/null
}
trap cleanup EXIT

expect_denied 'SELECT count(*) FROM management_ca' 'view access before role grant'
"$psql_bin" "$TRUST_RESTORE_ADMIN_URL" -X -v ON_ERROR_STOP=1 \
  -c 'GRANT trust_api_reader TO trust_restore_login_ci' >/dev/null

view_counts=$("$psql_bin" "$TRUST_RESTORE_READER_URL" -XAt -v ON_ERROR_STOP=1 \
  -c 'SELECT (SELECT count(*) FROM management_ca), (SELECT count(*) FROM management_certificate), (SELECT count(*) FROM management_audit), (SELECT count(*) FROM management_reader_scope)')
if [[ "$view_counts" != '2|1|1|1' ]]; then
  echo "Unexpected restored view counts: $view_counts" >&2
  exit 1
fi
expect_denied 'SELECT count(*) FROM certificate' 'raw certificate read'
expect_denied 'SELECT count(*) FROM management_reader_grant' 'raw reader-grant read'
expect_denied 'UPDATE ca SET display_name = display_name' 'CA write'

cleanup
trap - EXIT
expect_denied 'SELECT count(*) FROM management_ca' 'view access after role revocation'
echo 'PASS: restored login gains only reader views while granted and loses them on revoke'
