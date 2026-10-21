#!/usr/bin/env bash
set -euo pipefail

# The supplied URL must name a new, disposable PostgreSQL database. This is
# an upgrade regression for 0014-0052, not an online migration runner.
#
# 0014, 0015, 0016, 0018 and 0019 each run in one transaction and abort on
# pre-existing rows they cannot carry forward: a revocation with reason 7 or
# 8 (0014), any crl_publication row (0015, operation_ref etc. are NOT NULL
# without a default), a revocation date outside 1970..9999 (0016) or a
# suspension CPS reference without text (0018, 0019). This script checks
# that each aborts with nothing applied, that the migration succeeds once the
# operator has removed the offending row, and that legacy revocation rows
# survive and feed the CRL pipeline.
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

# 0016 refuses a revocation date the CRL builder cannot encode. A hold (6)
# is the only row the 0014 guard lets the operator delete.
psql_run -c "INSERT INTO revocation (ca_id, serial_der_content, reason_code, revoked_at, actor_id)
             VALUES ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', decode('02', 'hex'), 6,
                     '1969-07-20T20:17:00Z', 'legacy-officer')" >/dev/null
expect_abort migrations/0016_crl_robustness.sql revocation_revoked_at_range
expect_eq '0016 objects after abort' \
  "$(scalar "SELECT (to_regprocedure('abandon_stale_crl_reservations(uuid,interval)') IS NULL)::text
               || (SELECT count(*) FROM information_schema.columns
                   WHERE table_name = 'crl_publication' AND column_name = 'intent_recorded_at')")" \
  'true0'
psql_run -c "DELETE FROM revocation WHERE reason_code = 6" >/dev/null
psql_run -f migrations/0016_crl_robustness.sql >/dev/null
psql_run -f migrations/0017_crl_intent_ordering.sql >/dev/null

# 0018 refuses a blank suspension CPS reference, 0019 one without any
# letter or digit (a no-break space passes 0018 but not 0019).
psql_run -c "INSERT INTO ca_revocation_policy (ca_id, suspension_cps_ref)
             VALUES ('ffffffff-ffff-4fff-8fff-ffffffffffff', '   ')" >/dev/null
expect_abort migrations/0018_revocation_hygiene.sql suspension_cps_ref_not_blank
expect_eq '0018 objects after abort' \
  "$(scalar "SELECT count(*) FROM pg_constraint WHERE conname = 'suspension_cps_ref_not_blank'")" 0
psql_run -c "UPDATE ca_revocation_policy SET suspension_cps_ref = E'\\u00A0'
             WHERE ca_id = 'ffffffff-ffff-4fff-8fff-ffffffffffff'" >/dev/null
psql_run -f migrations/0018_revocation_hygiene.sql >/dev/null
expect_abort migrations/0019_revocation_review_fixes.sql suspension_cps_ref_not_blank
expect_eq '0019 objects after abort' \
  "$(scalar "SELECT count(*) FROM pg_get_functiondef('record_crl_intent(uuid,bigint,text,bytea,bytea,bigint,bigint,bigint)'::regprocedure) d
             WHERE d LIKE '%may already be signed%'")" 0
psql_run -c "UPDATE ca_revocation_policy SET suspension_cps_ref = 'CPS 4.9.13'
             WHERE ca_id = 'ffffffff-ffff-4fff-8fff-ffffffffffff'" >/dev/null
psql_run -f migrations/0019_revocation_review_fixes.sql >/dev/null
psql_run -f migrations/0020_crl_coverage_and_ordering.sql >/dev/null
psql_run -f migrations/0021_crl_operability.sql >/dev/null
psql_run -f migrations/0022_ca_issuer_binding.sql >/dev/null
psql_run -f migrations/0023_revocation_least_privilege.sql >/dev/null
psql_run -f migrations/0024_ca_admin_dual_control.sql >/dev/null
psql_run -f migrations/0025_status_change_lock_order.sql >/dev/null
psql_run -f migrations/0026_schema_change_audit.sql >/dev/null
psql_run -f migrations/0027_audit_chain.sql >/dev/null
psql_run -f migrations/0028_officer_credentials.sql >/dev/null
psql_run -f migrations/0029_signed_status_changes.sql >/dev/null
psql_run -f migrations/0030_crl_distribution.sql >/dev/null
psql_run -f migrations/0031_crl_expired_entry_pruning.sql >/dev/null
psql_run -f migrations/0032_crl_pruned_entries.sql >/dev/null
psql_run -f migrations/0033_crl_operator_ca_list.sql >/dev/null
psql_run -f migrations/0034_status_change_reads.sql >/dev/null
psql_run -f migrations/0035_issuance_least_privilege.sql >/dev/null
psql_run -f migrations/0036_precautionary_hold.sql >/dev/null
psql_run -f migrations/0037_signed_ca_admin.sql >/dev/null
psql_run -f migrations/0038_precautionary_hold_limit.sql >/dev/null
psql_run -f migrations/0039_signed_close.sql >/dev/null
psql_run -f migrations/0040_admin_credential_dual_control.sql >/dev/null
psql_run -f migrations/0041_signed_evidence_audit.sql >/dev/null
psql_run -f migrations/0042_signed_ca_admin_rejection.sql >/dev/null
psql_run -f migrations/0043_policy_and_reconciliation_least_privilege.sql >/dev/null
psql_run -f migrations/0044_pending_admin_changes.sql >/dev/null
psql_run -f migrations/0045_break_glass.sql >/dev/null
psql_run -f migrations/0046_breakglass_custodian_person.sql >/dev/null
psql_run -f migrations/0047_precautionary_hold_ca_limit.sql >/dev/null
psql_run -f migrations/0048_credential_registry_lock.sql >/dev/null
psql_run -f migrations/0049_open_challenge_cap.sql >/dev/null
psql_run -f migrations/0050_admin_change_ca_lookup.sql >/dev/null
psql_run -f migrations/0051_breakglass_review_evidence.sql >/dev/null
psql_run -f migrations/0052_admin_proposal_max_age.sql >/dev/null

psql_run -f tests/revocation_populated_upgrade_verify.sql >/dev/null

echo 'PASS: populated 0013 -> 0052 revocation upgrade aborts on unsupported rows and preserves legacy revocations'
