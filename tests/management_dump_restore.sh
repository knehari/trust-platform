#!/usr/bin/env bash
set -euo pipefail

# Use only disposable databases owned by the test operator. This rehearses a
# logical database restore, not CA key custody or production disaster recovery.
: "${TRUST_RESTORE_SOURCE_URL:?set TRUST_RESTORE_SOURCE_URL}"
: "${TRUST_RESTORE_TARGET_URL:?set TRUST_RESTORE_TARGET_URL to an empty database}"
psql_bin=${TRUST_PSQL_BIN:-psql}
dump_bin=${TRUST_PG_DUMP_BIN:-pg_dump}
restore_bin=${TRUST_PG_RESTORE_BIN:-pg_restore}

source_db=$("$psql_bin" "$TRUST_RESTORE_SOURCE_URL" -XAt -v ON_ERROR_STOP=1 -c 'SELECT current_database()')
target_db=$("$psql_bin" "$TRUST_RESTORE_TARGET_URL" -XAt -v ON_ERROR_STOP=1 -c 'SELECT current_database()')
if [[ "$source_db" == "$target_db" ]]; then
  echo 'Source and restore target must be different databases' >&2
  exit 1
fi
target_relations=$("$psql_bin" "$TRUST_RESTORE_TARGET_URL" -XAt -v ON_ERROR_STOP=1 \
  -c "SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r','p','v','m','S')")
if [[ "$target_relations" != 0 ]]; then
  echo 'Restore target must have no public relations' >&2
  exit 1
fi
target_reader_role=$("$psql_bin" "$TRUST_RESTORE_TARGET_URL" -XAt -v ON_ERROR_STOP=1 \
  -c "SELECT count(*) FROM pg_roles WHERE rolname = 'trust_api_reader' AND NOT rolcanlogin")
if [[ "$target_reader_role" != 1 ]]; then
  echo 'Restore target requires NOLOGIN trust_api_reader role' >&2
  exit 1
fi

source_fingerprint=$("$psql_bin" "$TRUST_RESTORE_SOURCE_URL" -XAt -v ON_ERROR_STOP=1 \
  -f tests/management_restore_fingerprint.sql)
if [[ -z "$source_fingerprint" ]]; then
  echo 'Source lacks the populated management fixture' >&2
  exit 1
fi
source_ledger_exists=$("$psql_bin" "$TRUST_RESTORE_SOURCE_URL" -XAt -v ON_ERROR_STOP=1 \
  -c "SELECT to_regclass('public.management_migration_ledger') IS NOT NULL")
if [[ "$source_ledger_exists" == t ]]; then
  source_ledger_rows=$("$psql_bin" "$TRUST_RESTORE_SOURCE_URL" -XAt -v ON_ERROR_STOP=1 \
    -c "SELECT COALESCE(jsonb_agg(to_jsonb(l) ORDER BY l.version)::text, '[]') FROM management_migration_ledger l")
fi

umask 077
backup_dir=$(mktemp -d "${TMPDIR:-/tmp}/trust-management-restore.XXXXXX")
trap 'rm -rf "$backup_dir"' EXIT
archive="$backup_dir/management.dump"
"$dump_bin" --format=custom --file="$archive" "$TRUST_RESTORE_SOURCE_URL"
test -s "$archive"
chmod 600 "$archive"
"$restore_bin" --single-transaction --exit-on-error --no-owner \
  --dbname="$TRUST_RESTORE_TARGET_URL" "$archive" >/dev/null

restored_fingerprint=$("$psql_bin" "$TRUST_RESTORE_TARGET_URL" -XAt -v ON_ERROR_STOP=1 \
  -f tests/management_restore_fingerprint.sql)
if [[ "$source_fingerprint" != "$restored_fingerprint" ]]; then
  echo 'Restored management rows differ from the source snapshot' >&2
  exit 1
fi
target_ledger_exists=$("$psql_bin" "$TRUST_RESTORE_TARGET_URL" -XAt -v ON_ERROR_STOP=1 \
  -c "SELECT to_regclass('public.management_migration_ledger') IS NOT NULL")
if [[ "$source_ledger_exists" != "$target_ledger_exists" ]]; then
  echo 'Restored migration ledger presence differs from the source snapshot' >&2
  exit 1
fi
if [[ "$source_ledger_exists" == t ]]; then
  restored_ledger_rows=$("$psql_bin" "$TRUST_RESTORE_TARGET_URL" -XAt -v ON_ERROR_STOP=1 \
    -c "SELECT COALESCE(jsonb_agg(to_jsonb(l) ORDER BY l.version)::text, '[]') FROM management_migration_ledger l")
  if [[ "$source_ledger_rows" != "$restored_ledger_rows" ]]; then
    echo 'Restored migration ledger rows differ from the source snapshot' >&2
    exit 1
  fi
fi
"$psql_bin" "$TRUST_RESTORE_TARGET_URL" -X -v ON_ERROR_STOP=1 \
  -f tests/management_api_readonly.sql >/dev/null

echo 'PASS: disposable management dump/restore preserved rows and reader privileges'
