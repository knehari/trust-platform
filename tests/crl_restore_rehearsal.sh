#!/usr/bin/env bash
# Lab-only rehearsal: a real logical backup (pg_dump --format=custom) is
# restored into an empty database (pg_restore, one transaction, owners and
# ACLs kept), and crl_restore_revocations then re-applies, on that restored
# database, a revocation that the restored data does not hold but a later
# published CRL lists (migration 0060).
# Needs the files written by the PostgreSQL test
# revocations_lost_in_a_restore_are_reapplied_from_the_published_crl with
# TRUST_CRL_EXPORT_DIR (<dir>/restore), run BEFORE
# tests/crl_restore_revocations.sh (the source must not have applied CRL 7
# yet), a superuser source URL, an empty target database in the same
# cluster, and PostgreSQL 16 client tools:
#   TRUST_CI_DATABASE_URL=... TRUST_RESTORE_TARGET_URL=... \
#     bash tests/crl_restore_rehearsal.sh <dir>
set -euo pipefail
: "${TRUST_CI_DATABASE_URL:?TRUST_CI_DATABASE_URL is required}"
: "${TRUST_RESTORE_TARGET_URL:?TRUST_RESTORE_TARGET_URL must name an empty database}"
src="$TRUST_CI_DATABASE_URL"
dst="$TRUST_RESTORE_TARGET_URL"
dir="${1:?usage: $0 <export dir>}/restore"
umask 077
temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT
fail() { echo "FAIL: $*" >&2; cat "$temp/out" "$temp/err" 2>/dev/null >&2; exit 1; }
sql() { local db="$1"; shift; psql -X -q -A -t -v ON_ERROR_STOP=1 "$db" -c "$1"; }
read -r ca s3 lost <"$dir/ids"

[ "$(sql "$src" 'SELECT current_database()')" != "$(sql "$dst" 'SELECT current_database()')" ] \
  || fail "source and restore target must be different databases"
[ "$(sql "$dst" "SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace")" = 0 ] \
  || fail "restore target must be empty"
[ "$(sql "$src" "SELECT certificate_status('$ca', '\\x$s3')")" = VALID ] \
  || fail "run before tests/crl_restore_revocations.sh: s3 is already revoked in the source"

# The backup, taken before CRL 7 (which revokes s3) was published.
pg_dump --format=custom --file="$temp/backup.dump" "$src"
pg_restore --exit-on-error --single-transaction --dbname="$dst" "$temp/backup.dump"
[ "$(sql "$dst" "SELECT certificate_status('$ca', '\\x$s3')")" = VALID ] \
  || fail "restored database does not show the lost revocation as VALID"
before_floor="$(sql "$dst" "SELECT coalesce(max(floor), 0) FROM crl_number_floor WHERE ca_id = '$ca'")"

cargo build -q --locked -p trust-management-api --bin crl_restore_revocations
status=0
TRUST_DATABASE_TLS=disable-lab TRUST_DATABASE_URL="$dst" target/debug/crl_restore_revocations \
  "$ca" "$dir/crl7.der" --reason "rehearsal: pg_restore of a backup older than CRL 7" \
  >"$temp/out" 2>"$temp/err" || status=$?
[ "$status" -eq 2 ] || fail "expected exit 2 (unknown certificate reported), got $status"
grep -qx "serial=$s3 outcome=RESTORED" "$temp/out" || fail "s3 not restored on the restored database"
grep -qx "serial=$lost outcome=UNKNOWN_CERTIFICATE" "$temp/out" || fail "unknown certificate not reported"
[ "$(sql "$dst" "SELECT certificate_status('$ca', '\\x$s3')")" = REVOKED ] \
  || fail "s3 is not REVOKED on the restored database"
[ "$(sql "$dst" "SELECT max(floor) FROM crl_number_floor WHERE ca_id = '$ca'")" = 7 ] \
  || fail "floor not raised from $before_floor to 7"
[ "$(sql "$dst" "SELECT count(*) FROM crl_restore WHERE ca_id = '$ca' AND crl_number = 7")" = 1 ] \
  || fail "CRL 7 not kept as evidence"
# The restored database's next CRL is numbered above the published one.
[ "$(sql "$dst" "SELECT crl_number FROM reserve_crl('$ca', 'rehearsal', 'rehearsal-next')")" = 8 ] \
  || fail "next CRL on the restored database is not numbered 8"
[ "$(sql "$dst" "SELECT count(*) FROM crl_entry_snapshot WHERE ca_id = '$ca' AND crl_number = 8
                  AND serial_der_content = '\\x$s3'")" = 1 ] \
  || fail "the next CRL on the restored database does not list s3"
# The source was not touched.
[ "$(sql "$src" "SELECT certificate_status('$ca', '\\x$s3')")" = VALID ] || fail "source changed"
echo "PASS: after a real pg_restore of an older backup, crl_restore_revocations re-applies the published revocation and the next CRL lists it"
