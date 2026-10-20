#!/usr/bin/env bash
set -euo pipefail

# The supplied URL must name a new, disposable PostgreSQL database. This is
# an upgrade regression for 0014-0016, not an online migration runner.
#
# 0014 and 0015 each run in one transaction and abort on pre-existing rows
# they cannot carry forward: a revocation with reason 7 or 8 (0014) or any
# crl_publication row (0015, operation_ref etc. are NOT NULL without a
# default). This script checks that both abort with nothing applied, that the
# migration succeeds once the operator has removed the offending row, and that
# legacy revocation rows survive and feed the CRL pipeline.
: "${TRUST_UPGRADE_DATABASE_URL:?set TRUST_UPGRADE_DATABASE_URL to an empty disposable database}"
psql_bin=${TRUST_PSQL_BIN:-psql}

psql_run() {
  "$psql_bin" "$TRUST_UPGRADE_DATABASE_URL" -X -q -v ON_ERROR_STOP=1 "$@"
}
scalar() {
  psql_run -At -c "$1"
}
expect_abort() { # <migration> <expected error substring>
  local out
  if out=$(psql_run -f "$1" 2>&1 >/dev/null); then
    echo "FAIL: $1 applied although it must abort on pre-existing rows" >&2
    exit 1
  fi
  if ! grep -qF -- "$2" <<<"$out"; then
    echo "FAIL: $1 aborted for an unexpected reason:" >&2
    echo "$out" >&2
    exit 1
  fi
}
expect_eq() { # <description> <actual> <expected>
  if [ "$2" != "$3" ]; then
    echo "FAIL: $1: got '$2', expected '$3'" >&2
    exit 1
  fi
}

if [ "$(scalar "SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace")" != 0 ]; then
  echo "FAIL: TRUST_UPGRADE_DATABASE_URL must name an empty database" >&2
  exit 1
fi

for migration in migrations/000*.sql migrations/0010*.sql migrations/0011*.sql \
                 migrations/0012*.sql migrations/0013*.sql; do
  psql_run -f "$migration" >/dev/null
done
psql_run -f tests/management_populated_upgrade_seed.sql >/dev/null
psql_run -f tests/revocation_populated_upgrade_seed.sql >/dev/null

# 0014 refuses the removeFromCRL row and leaves nothing behind.
expect_abort migrations/0014_revocation_lifecycle.sql revocation_reason_code_accepted
expect_eq '0014 objects after abort' \
  "$(scalar "SELECT (to_regclass('ca_revocation_policy') IS NULL)::text
               || (to_regprocedure('certificate_status(uuid,bytea)') IS NULL)::text
               || (SELECT count(*) FROM information_schema.columns
                   WHERE table_name = 'revocation' AND column_name = 'change_id')")" \
  'truetrue0'
expect_eq 'revocation rows after 0014 abort' "$(scalar 'SELECT count(*) FROM revocation')" 2

# removeFromCRL means "not revoked": the operator deletes the row, then retries.
psql_run -c "DELETE FROM revocation WHERE reason_code = 8" >/dev/null
psql_run -f migrations/0014_revocation_lifecycle.sql >/dev/null

# 0015 refuses a pre-existing (0001-shaped) crl_publication row.
psql_run -c "INSERT INTO crl_publication (ca_id, crl_number, this_update, next_update, crl_sha256)
             VALUES ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 7, '2026-10-04T00:00:00Z',
                     '2026-10-11T00:00:00Z', decode(repeat('06', 32), 'hex'))" >/dev/null
expect_abort migrations/0015_crl_pipeline.sql 'column "operation_ref" of relation "crl_publication" contains null values'
expect_eq '0015 objects after abort' \
  "$(scalar "SELECT (to_regclass('crl_entry_snapshot') IS NULL)::text
               || (to_regprocedure('reserve_crl(uuid,text,text)') IS NULL)::text
               || (SELECT count(*) FROM information_schema.columns
                   WHERE table_name = 'crl_publication' AND column_name = 'status')
               || (SELECT data_type FROM information_schema.columns
                   WHERE table_name = 'crl_publication' AND column_name = 'crl_number')")" \
  'truetrue0numeric'
expect_eq 'crl_publication rows after 0015 abort' "$(scalar 'SELECT count(*) FROM crl_publication')" 1

# A lab CRL without intent, DER or snapshot cannot be carried forward; the
# operator removes it (no guard exists before 0015), then retries.
psql_run -c "DELETE FROM crl_publication" >/dev/null
psql_run -f migrations/0015_crl_pipeline.sql >/dev/null
psql_run -f migrations/0016_crl_robustness.sql >/dev/null

psql_run -f tests/revocation_populated_upgrade_verify.sql >/dev/null

echo 'PASS: populated 0013 -> 0016 revocation upgrade aborts on unsupported rows and preserves legacy revocations'
