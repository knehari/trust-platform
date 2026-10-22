#!/usr/bin/env bash
set -euo pipefail

# The target must be a disposable, empty database with the reader role present.
: "${TRUST_RESTORE_SOURCE_URL:?set TRUST_RESTORE_SOURCE_URL}"
: "${TRUST_RESTORE_TARGET_URL:?set TRUST_RESTORE_TARGET_URL}"
psql_bin=${TRUST_PSQL_BIN:-psql}

"$psql_bin" "$TRUST_RESTORE_TARGET_URL" -X -v ON_ERROR_STOP=1 \
  -f tests/management_restore_fault.sql >/dev/null
cleanup() {
  "$psql_bin" "$TRUST_RESTORE_TARGET_URL" -X -v ON_ERROR_STOP=1 \
    -c 'DROP EVENT TRIGGER IF EXISTS management_restore_fault; DROP FUNCTION IF EXISTS management_restore_fault()' >/dev/null
}
trap cleanup EXIT

if output=$(bash tests/management_dump_restore.sh 2>&1); then
  echo 'Restore unexpectedly succeeded with the fault trigger active' >&2
  exit 1
fi
if [[ "$output" != *'intentional lab restore fault'* ]]; then
  echo 'Restore failed for a reason other than the injected fault' >&2
  echo "$output" >&2
  exit 1
fi

remaining_relations=$("$psql_bin" "$TRUST_RESTORE_TARGET_URL" -XAt -v ON_ERROR_STOP=1 \
  -c "SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r','p','v','m','S')")
if [[ "$remaining_relations" != 0 ]]; then
  echo "Failed restore left $remaining_relations public relations" >&2
  exit 1
fi
echo 'PASS: failed restore left no public relations'

cleanup
trap - EXIT
bash tests/management_dump_restore.sh
echo 'PASS: restore retry succeeded after fault removal'
